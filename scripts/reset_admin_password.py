#!/usr/bin/env python3
"""CSAI admin 密码重置脚本——直接 UPDATE PostgreSQL rbac_users

用法:
  python3 reset_admin_password.py            # 生成随机强密码
  python3 reset_admin_password.py 新密码      # 指定密码

依赖: python3 bcrypt（无则 pip install bcrypt）+ psql
"""
import os, sys, subprocess, secrets, string, bcrypt, re

PG_HOST = os.environ.get('CSAI_PG_HOST', '127.0.0.1')
PG_PORT = os.environ.get('CSAI_PG_PORT', '5433')
PG_USER = os.environ.get('CSAI_PG_USER', 'cyberstrike')
PG_DB = os.environ.get('CSAI_PG_DB', 'cyberstrike')

def pg_password_from_config():
    """从 config.yaml 的 database.dsn 提取密码（避免硬编码）"""
    cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.yaml')
    try:
        with open(cfg, encoding='utf-8') as f:
            content = f.read()
        m = re.search(r'dsn:\s*postgres://[^:]+:([^@]+)@', content)
        if m:
            return re.sub(r'%40', '@', m.group(1))
    except Exception:
        pass
    return ''

PG_PASSWORD = os.environ.get('CSAI_PG_PASSWORD', '') or pg_password_from_config()
if not PG_PASSWORD:
    print('错误: 未找到数据库密码——请设置环境变量 CSAI_PG_PASSWORD 或在 config.yaml 配置 database.dsn')
    sys.exit(1)

def gen_password(length=20):
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*-_=+'
    # 保证至少 1 字母 1 数字 1 特殊字符
    pw = [secrets.choice(string.ascii_letters),
          secrets.choice(string.digits),
          secrets.choice('!@#$%^&*-_=+')]
    pw += [secrets.choice(alphabet) for _ in range(length - 3)]
    secrets.SystemRandom().shuffle(pw)
    return ''.join(pw)

def main():
    password = sys.argv[1] if len(sys.argv) > 1 else gen_password()
    if len(password) < 8:
        print('密码太短（至少 8 位）')
        sys.exit(1)

    # 生成 bcrypt hash（$2b$ 前缀 PG 可存）
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=10)).decode('utf-8')

    sql = f"UPDATE rbac_users SET password_hash='{password_hash}' WHERE username='admin' AND is_builtin=1;"
    env = {**os.environ, 'PGPASSWORD': PG_PASSWORD}
    try:
        result = subprocess.run(
            ['psql', '-h', PG_HOST, '-p', PG_PORT, '-U', PG_USER, '-d', PG_DB, '-c', sql],
            capture_output=True, text=True, timeout=15, env=env)
    except FileNotFoundError:
        print('psql 不存在——请安装 postgresql-client')
        sys.exit(1)

    if result.returncode != 0:
        print(f'UPDATE 失败: {result.stderr.strip()}')
        sys.exit(1)

    print('✅ admin 密码已更新（直接数据库 UPDATE）')
    print(f'  用户名: admin')
    print(f'  新密码: {password}')
    print(f'  hash: {password_hash[:20]}...（bcrypt $2b$10$）')
    print('  登录: https://127.0.0.1:8080/（或已配置的公网入口）')

if __name__ == '__main__':
    main()
