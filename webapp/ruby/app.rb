require 'sinatra/base'
require 'digest/sha2'
require 'mysql2-cs-bind'
require 'rack-flash'
require 'json'
require 'erubis'
require 'rack-lineprof' if ENV['ENABLE_RACK_LINEPROF']
require 'redis'

module Isucon4
  class App < Sinatra::Base
    use Rack::Lineprof, profile: 'app.rb' if ENV['ENABLE_RACK_LINEPROF']
    use Rack::Session::Cookie, secret: ENV['ISU4_SESSION_SECRET'] || 'shirokane'
    set :public_folder, File.expand_path('../../public', __FILE__)

    helpers do
      def config
        @config ||= {
          user_lock_threshold: (ENV['ISU4_USER_LOCK_THRESHOLD'] || 3).to_i,
          ip_ban_threshold: (ENV['ISU4_IP_BAN_THRESHOLD'] || 10).to_i,
        }
      end

      def db
        Thread.current[:isu4_db] ||= Mysql2::Client.new(
          host: ENV['ISU4_DB_HOST'] || 'localhost',
          port: ENV['ISU4_DB_PORT'] ? ENV['ISU4_DB_PORT'].to_i : nil,
          username: ENV['ISU4_DB_USER'] || 'root',
          password: ENV['ISU4_DB_PASSWORD'],
          database: ENV['ISU4_DB_NAME'] || 'isu4_qualifier',
          reconnect: true,
        )
      end

      def redis
        Thread.current[:isu4_redis] ||= Redis.new(path: "/tmp/redis.sock", driver: 'hiredis')
      end

      def calculate_password_hash(password, salt)
        Digest::SHA256.hexdigest "#{password}:#{salt}"
      end

      def redis_key_user(login)
        "isu4:login_fail:user:#{login}"
      end

      def redis_key_ip
        "isu4:login_fail:ip:#{request.ip}"
      end

      def redis_last_login_key(user_id)
        "isu4:login_log:user:#{user_id}"
      end

      def redis_last_before_login_key(user_id)
        "isu4:login_log_before:user:#{user_id}"
      end

      def update_last_login(user_id)
        last_key        = redis_last_login_key(user_id)
        last_before_key = redis_last_before_login_key(user_id)

        %w(ip date).each {|k| redis.hset(last_before_key, k, redis.hget(last_key, k))}

        redis.hset(last_key, 'ip',   request.ip)
        redis.hset(last_key, 'date', Time.now.strftime("%Y-%m-%d %H:%M:%S"))
      end

      def login_log(succeeded, login, user_id = nil)
        if succeeded
          redis.del(redis_key_ip)
          if user_id
            redis.del(redis_key_user(user_id))
            update_last_login(user_id)
          end
        else
          redis.incr(redis_key_ip)
          redis.incr(redis_key_user(user_id)) if user_id
        end
      end

      def user_locked?(user)
        return nil unless user
        config[:user_lock_threshold] <= redis.get(redis_key_user(user['id'])).to_i
      end

      def ip_banned?
        config[:ip_ban_threshold] <= redis.get(redis_key_ip).to_i
      end

      def attempt_login(login, password)
        user = db.xquery('SELECT id, salt, password_hash FROM users WHERE login = ?', login).first

        if ip_banned?
          login_log(false, login, user ? user['id'] : nil)
          return [nil, :banned]
        end

        if user_locked?(user)
          login_log(false, login, user['id'])
          return [nil, :locked]
        end

        if user && calculate_password_hash(password, user['salt']) == user['password_hash']
          login_log(true, login, user['id'])
          [user, nil]
        elsif user
          login_log(false, login, user['id'])
          [nil, :wrong_password]
        else
          login_log(false, login)
          [nil, :wrong_login]
        end
      end

      def current_user
        return @current_user if @current_user
        return nil unless session[:user_id]

        @current_user = db.xquery('SELECT * FROM users WHERE id = ?', session[:user_id].to_i).first
        unless @current_user
          session[:user_id] = nil
          return nil
        end

        @current_user
      end

      def last_login
        return nil unless current_user
        key = redis_last_before_login_key(session[:user_id])
        {ip: redis.hget(key, 'ip'), login: current_user['login'], date: redis.hget(key, 'date')}
      end

      def banned_ips
        threshold = config[:ip_ban_threshold]

        redis.keys("isu4:login_fail:ip:*").select do |k|
          redis.get(k).to_i >= threshold
        end.map do |k|
          k.split(':').last
        end
      end

      def locked_users
        threshold = config[:user_lock_threshold]

        redis.keys("isu4:login_fail:user:*").select do |k|
          redis.get(k).to_i >= threshold
        end.map do |k|
          user_id = k.split(':').last
          db.xquery('SELECT login FROM users WHERE id = ?', user_id).first['login']
        end
      end
    end

    get '/' do
      erb :index, layout: :base
    end

    post '/login' do
      user, err = attempt_login(params[:login], params[:password])
      if user
        session[:user_id] = user['id']
        redirect '/mypage'
      else
        case err
        when :locked
          redirect to('/?error=locked')
        when :banned
          redirect to('/?error=banned')
        else
          redirect to('/?error=wrong')
        end
      end
    end

    get '/mypage' do
      unless current_user
        redirect to('/?error=not_login')
      end
      erb :mypage, layout: :base
    end

    get '/report' do
      redis.save

      content_type :json
      {
        banned_ips: banned_ips,
        locked_users: locked_users,
      }.to_json
    end
  end
end
