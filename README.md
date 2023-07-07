# Cloud-server-security_scan
# 以上为云服务器前期配置检测小工具
# 安全扫描工具
这是一个用于进行安全扫描的工具，用于检查服务器、文件目录、容器镜像以及其他资源是否存在敏感信息泄露的风险。
## 使用方法
1. 下载并安装 Python 程序运行环境（版本要求：Python 3.6+）
2. 安装所需的依赖库：`pip install paramiko docker requests`
3. 创建一个名为 `security_scan.py` 的文件，并将上述代码复制到该文件中
4. 打开终端或命令提示符，并进入 `security_scan.py` 文件所在的目录
5. 运行命令 `python security_scan.py`，将会提示输入以下参数：

   - `--ip`：服务器IP地址
   - `--username`：SSH用户名
   - `--password`：SSH密码
   - `--directory`：要扫描的文件目录路径
   - `--docker_image`：要扫描的Docker镜像名称
   如果不提供参数，则程序会要求您在终端逐个输入参数。
1. 程序将会连接到指定的服务器，并开始对目标资源进行安全扫描。它将执行以下操作：
   - 检查文件是否包含SDK的敏感信息
   - 检查文件是否包含账号密码信息
   - 检查前端代码是否包含敏感信息
   - 检查Docker镜像是否包含敏感信息
   - 检查临时访问凭证是否泄露
   - 检查API是否泄露
扫描结果将在终端显示出来，指示是否发现了敏感信息泄露的风险。
## 示例
以下是一个使用示例：
```
python security_scan.py --ip 192.168.1.100 --username admin --password 123456 --directory /var/www/html --docker_image myapp:latest
```
## 注意事项
- 使用本工具前，请确保您有合法的权限来执行安全扫描操作。
- 此工具提供了基本的敏感信息检测功能，但仍建议您根据实际情况进行定制和扩展。 
- 在运行此程序之前，请谨慎备份相关资源，以免意外删除或更改文件。 
请根据您的实际需求进行适当修改和完善代码。