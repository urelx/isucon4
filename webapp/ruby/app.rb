require 'sinatra/base'
require 'digest/sha2'
require 'jdbc/mysql'
require 'jdbc-helper'
require 'rack-flash'
require 'json'

module Isucon4
  class App < Sinatra::Base
    use Rack::Session::Cookie, secret: ENV['ISU4_SESSION_SECRET'] || 'shirokane'
    use Rack::Flash
    set :public_folder, File.expand_path('../../public', __FILE__)

    helpers do
      def config
        @config ||= {
          user_lock_threshold: (ENV['ISU4_USER_LOCK_THRESHOLD'] || 3).to_i,
          ip_ban_threshold: (ENV['ISU4_IP_BAN_THRESHOLD'] || 10).to_i,
        }
      end

      def db
        Jdbc::MySQL.load_driver
        Thread.current[:isu4_db] ||= JDBCHelper::MySQL.connect('localhost', 'root','','isu4_qualifier')
        # Thread.current[:isu4_db] ||= Mysql2::Client.new(
        #   host: ENV['ISU4_DB_HOST'] || 'localhost',
        #   port: ENV['ISU4_DB_PORT'] ? ENV['ISU4_DB_PORT'].to_i : nil,
        #   username: ENV['ISU4_DB_USER'] || 'root',
        #   password: ENV['ISU4_DB_PASSWORD'],
        #   database: ENV['ISU4_DB_NAME'] || 'isu4_qualifier',
        #   reconnect: true,
        # )
      end

      def calculate_password_hash(password, salt)
        Digest::SHA256.hexdigest "#{password}:#{salt}"
      end

      def login_log(succeeded, login, user_id = nil)
        table = db.table('isu4_qualifier.login_log')
        table.insert(created_at: Time.now, user_id: user_id, login: login, ip: request.ip, succeeded: succeeded ? 1 : 0)
      end

      def user_locked?(user)
        return nil unless user
        log = db.query("SELECT COUNT(1) AS failures FROM login_log WHERE user_id = '%s' AND id > IFNULL((select id from login_log where user_id = '%s' AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0);" % [user['id'], user['id']]).first

        config[:user_lock_threshold] <= log['failures']
      end

      def ip_banned?
        log = db.query("SELECT COUNT(1) AS failures FROM login_log WHERE ip = '%s' AND id > IFNULL((select id from login_log where ip = '%s' AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0);" % [request.ip, request.ip]).first

        config[:ip_ban_threshold] <= log['failures']
      end

      def attempt_login(login, password)
        user = db.query("SELECT * FROM users WHERE login = '%s'" % login).first

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

        @current_user = db.query('SELECT * FROM users WHERE id = %d' % session[:user_id].to_i).first
        unless @current_user
          session[:user_id] = nil
          return nil
        end

        @current_user
      end

      def last_login
        return nil unless current_user

        r = db.query('SELECT * FROM login_log WHERE succeeded = 1 AND user_id = "%s" ORDER BY id DESC LIMIT 2' % current_user['id']).to_a.last.to_h
        r["created_at"] = Time.at(r["created_at"].getTime/1000)
        r
      end

      def banned_ips
        ips = []
        threshold = config[:ip_ban_threshold]

        not_succeeded = db.query('SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= "%s"' % threshold)

        ips.concat not_succeeded.each.map { |r| r['ip'] }

        last_succeeds = db.query('SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip')

        last_succeeds.each do |row|
          count = db.query('SELECT COUNT(1) AS cnt FROM login_log WHERE ip = "%s" AND "%s" < id' % [row['ip'], row['last_login_id']]).first['cnt']
          if threshold <= count
            ips << row['ip']
          end
        end

        ips
      end

      def locked_users
        user_ids = []
        threshold = config[:user_lock_threshold]

        not_succeeded = db.query('SELECT user_id, login FROM (SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= "%s"' % threshold)

        user_ids.concat not_succeeded.each.map { |r| r['login'] }

        last_succeeds = db.query('SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id')

        last_succeeds.each do |row|
          count = db.query('SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = "%s" AND "%s" < id' % [row['user_id'], row['last_login_id']]).first['cnt']
          if threshold <= count
            user_ids << row['login']
          end
        end

        user_ids
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
          flash[:notice] = "This account is locked."
        when :banned
          flash[:notice] = "You're banned."
        else
          flash[:notice] = "Wrong username or password"
        end
        redirect '/'
      end
    end

    get '/mypage' do
      unless current_user
        flash[:notice] = "You must be logged in"
        redirect '/'
      end
      erb :mypage, layout: :base
    end

    get '/report' do
      content_type :json
      {
        banned_ips: banned_ips,
        locked_users: locked_users,
      }.to_json
    end
  end
end
