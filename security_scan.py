import argparse
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
import boto3
import requests
import paramiko
import re
from datetime import datetime

def check_api_leak(username, password, api_endpoints):
    for endpoint in api_endpoints:
        url = f"{endpoint}/v1/api"
        response = requests.get(url, auth=(username, password))

        if response.status_code == 200:
            if "Access denied" not in response.text:
                print(f"API leaked: {username}:{password} - {url}")
                # 添加进一步的处理逻辑，如发送通知邮件等


def check_password_leak(username, password, websites):
    for website in websites:
        url = f"{website}/search?query={username}:{password}"
        response = requests.get(url)

        if response.status_code == 200:
            if "No results found" not in response.text:
                print(f"Account leaked: {username}:{password} - {url}")
                # 添加进一步的处理逻辑，如发送通知邮件等


def check_temp_credential_leak(access_key, secret_key, temp_credential_endpoints):
    for endpoint in temp_credential_endpoints:
        url = f"{endpoint}/v1/temp_credential"
        headers = {
            "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{datetime.now().strftime('%Y%m%d')}/us-east-1/service/aws4_request, "
                             f"SignedHeaders=host;x-amz-date, "
                             f"Signature=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "x-amz-date": datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"),
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            if "Access denied" not in response.text:
                print(f"Temporary credential leaked: {access_key}:{secret_key} - {url}")
                # 添加进一步的处理逻辑，如发送通知邮件等


def connect_to_server(server_ip, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server_ip, username=username, password=password)

        return client
    except paramiko.AuthenticationException:
        print("Failed to authenticate SSH connection.")
    except paramiko.SSHException as e:
        print(f"SSH connection failed: {str(e)}")
    except paramiko.Exception as e:
        print(f"An error occurred while connecting to the server: {str(e)}")

    return None


def check_file_for_sdk(file_path, client):
    sftp = client.open_sftp()
    with sftp.file(file_path, "r") as file:
        content = file.read()
        pattern = r"(sdk_key|sdk_secret|access_token)[\s:=]+'(.+?)'"
        matches = re.findall(pattern, content)
        if matches:
            print(f"SDK sensitive information found in file: {file_path}")
            for match in matches:
                print(f"- {match[0]}: {match[1]}")


def traverse_directory_for_sdk(directory, client):
    stdin, stdout, stderr = client.exec_command(f"find {directory} -type f")
    file_paths = stdout.read().decode().splitlines()
    for file_path in file_paths:
        check_file_for_sdk(file_path, client)


def check_sdk_leaks(server_ip, username, password, directory_to_scan, websites):
    # 检查账号密码泄露
    check_password_leak(username, password, websites)

    # 连接到云服务器
    client = connect_to_server(server_ip, username, password)
    if client:
        # 在指定目录下检查SDK敏感信息
        traverse_directory_for_sdk(directory_to_scan, client)
        client.close()


def check_shared_snapshots_aws():
    ec2_client = boto3.client('ec2')

    response = ec2_client.describe_snapshots(OwnerIds=['self'])

    shared_snapshots = []
    for snapshot in response['Snapshots']:
        if 'CreateVolumePermission' in snapshot:
            permissions = snapshot['CreateVolumePermission']
            for permission in permissions:
                if permission['Group'] == 'all':
                    shared_snapshots.append(snapshot['SnapshotId'])

    return shared_snapshots


def check_shared_snapshots_azure():
    subscription_id = 'your_subscription_id'
    credential = DefaultAzureCredential()
    compute_client = ComputeManagementClient(credential, subscription_id)

    snapshots = compute_client.snapshots.list()

    shared_snapshots = []
    for snapshot in snapshots:
        if snapshot.permissions and 'public' in snapshot.permissions.to_dict():
            shared_snapshots.append(snapshot.id)

    return shared_snapshots
# 从文件读取敏感文件列表
def read_sensitive_files(file_path):
    with open(file_path, 'r') as f:
        sensitive_files = [line.strip() for line in f.readlines()]
    return sensitive_files


# 目录枚举和敏感文件检测函数
def directory_enum(base_url, directories, sensitive_files):
    for directory in directories:
        for file in sensitive_files:
            url = base_url + directory + file
            response = requests.get(url)
            if response.status_code == 200:
                print(f"敏感文件发现：{url}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="云安全项目")
    subparsers = parser.add_subparsers(dest="command", help="可用的子命令")

    # 子命令1：检测云服务器共享快照泄露
    parser_check_snapshots = subparsers.add_parser("check-snapshots", help="检测云服务器共享快照泄露")
    parser_check_snapshots.add_argument("cloud_provider", choices=["aws", "azure"], help="云服务提供商")
    parser_check_snapshots.add_argument("-f", "--file", help="包含订阅ID或凭据的文件路径")

    # 子命令2：检测云服务器前端代码泄露
    parser_check_leakage = subparsers.add_parser("check-leakage", help="检测云服务器前端代码泄露")
    parser_check_leakage.add_argument("url", help="要检测的目标URL（如 https://example.com/）")
    parser_check_leakage.add_argument("directories", nargs="+", help="要检测的目录，以空格分隔")
    parser_check_leakage.add_argument("-f", "--file", help="敏感文件列表的文件路径")

    # 子命令3：综合云安全检查
    parser_check_security = subparsers.add_parser("check-security", help="综合云安全检查")
    parser_check_security.add_argument("username", help="账号的用户名")
    parser_check_security.add_argument("password", help="账号的密码")
    parser_check_security.add_argument("--file", help="包含网站URL的文件路径")

    args = parser.parse_args()

    if args.command == "check-snapshots":
        # 执行检测云服务器共享快照泄露的代码
        if args.cloud_provider == "aws":
            check_shared_snapshots_aws(args.file)
        elif args.cloud_provider == "azure":
            check_shared_snapshots_azure(args.file)

    elif args.command == "check-leakage":
        # 执行检测云服务器前端代码泄露的代码
        read_sensitive_files(args.file)
        for directory in args.directories:
            directory_enum(args.url, directory)

    elif args.command == "check-security":
        # 执行综合云安全检查的代码
        username = args.username
        password = args.password
        websites = []
        with open(args.file, "r") as f:
            websites = [line.strip() for line in f]

        check_api_leak(username, password, websites)
        check_password_leak(username, password, websites)
        check_temp_credential_leak(username, password, websites)
