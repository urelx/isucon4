require 'mysql2-cs-bind'
require 'redis'

db = Mysql2::Client.new(
  host: ENV['ISU4_DB_HOST'] || 'localhost',
  port: ENV['ISU4_DB_PORT'] ? ENV['ISU4_DB_PORT'].to_i : nil,
  username: ENV['ISU4_DB_USER'] || 'root',
  password: ENV['ISU4_DB_PASSWORD'],
  database: ENV['ISU4_DB_NAME'] || 'isu4_qualifier',
  reconnect: true,
)

redis = Redis.new(path: "/tmp/redis.sock")

redis.keys("isu4*").each {|k| redis.del(k)}

user_count = Hash.new(0)
ip_count   = Hash.new(0)

db.xquery("SELECT * from login_log").each do |row|
  if row['succeeded'] == 1
    ip_count[row['ip']] = 0
    user_count[row['user_id']] = 0
    redis.hset("isu4:login_log:user:#{row['user_id']}", 'ip', row['ip'])
    redis.hset("isu4:login_log:user:#{row['user_id']}", 'date', row['created_at'].to_s)
  else
    ip_count[row['ip']] += 1
    user_count[row['user_id']] += 1
  end
end

user_count.each do |user_id, count|
  redis.set("isu4:login_fail:user:#{user_id}", count)
end

ip_count.each do |ip, count|
  redis.set("isu4:login_fail:ip:#{ip}", count)
end
