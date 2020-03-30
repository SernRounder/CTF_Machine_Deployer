from flask import Flask, render_template, request, make_response
import hashlib
import os
import subprocess
import random
app = Flask(__name__)

baseUrl = 'base.sern.site'
imageID = '703cacf23a52'
innerPort = 8888
deployPort = 5000   
startPort = 6000
endPort = 6666

runOrder = 'docker run -p {port}:{inPort} --rm -d {ID}'
stopOrder = 'docker kill {ID}'
clearOrder = 'python /home/rounder/flask/autoDeploy/helper.py {port} {uri} {passcode}'

userDic = {}

clearcode = str(random.random())
portList = set(i for i in range(startPort, endPort))

containerDic = {}
'''
{
    user:
    [containerID,port]
}
'''
############路由#################


@app.route('/register', methods=['GET'])  # 用户注册页面
def reg():
    user = request.args.get("name")
    if not user:  # 用户名空
        return render_template("reg.html")
    passwd = request.args.get("passwd").encode('utf-8')
    if user not in userDic.keys():  # 新用户
        md5hash = hashlib.md5(passwd)
        md5 = md5hash.hexdigest()
        userDic[user] = md5
    else:
        return "用户名冲突"
    return '注册成功, <a href="/"><button type="button">点此登录</button></a>'


@app.route("/")  # 根目录
def root():
    user = request.cookies.get('username')
    if check(user):  # cookies校验通过
        return render_template("user.html", user=user)
    return render_template("index.html")  # 登录页面


@app.route('/deploy')  # 部署验证
def deploy():
    user = request.cookies.get('username')
    if(check(user)):
        return doDeply(user)
    return "Die Hacker!!"


@app.route("/destory")  # 销毁验证
def destory():
    user = request.cookies.get('username')
    if(check(user)):
        return doDestory(user)
    return "Die Hacker!!"


@app.route("/login", methods=['GET'])  # 登录
def login():
    user = request.args.get("name")
    if not user:
        return '请输入正确的用户名<meta http-equiv="refresh" content="2;url=/">'
    passwd = request.args.get("passwd").encode('utf-8')
    md5hash = hashlib.md5(passwd)
    md5 = md5hash.hexdigest()
    if user in userDic.keys() and userDic[user] == md5:
        resp = make_response(
            '<h1>登录成功</h1><meta http-equiv="refresh" content="1;url=/">')  # 设置cookie
        resp.set_cookie('username', user)
        resp.set_cookie('userpass', md5)
        return resp
    else:
        return '用户名或密码错误<meta http-equiv="refresh" content="2;url=/">'


##########辅助路由#####################
@app.route('/container/<passcode>')
def clear(passcode):  # 自动清理
    if clearcode == passcode:
        order = 'docker ps'
        ret = os.popen(order).read().split('\n')[1:]
        for cont in ret:
            if imageID not in cont:  # 判断容器是否为目标容器
                continue
            if 'hour' in cont:  # 容器超时
                aimID = cont[:12]
                cf = 0
                for user in containerDic:
                    if containerDic[user][0][:12] == aimID:
                        doDestory(user)
                        cf = 1
                        break
                if cf:
                    print('STOP ERRROR!!, id=', aimID)
                    stopContainer(aimID)
        return "Done!"
    else:
        return "Fvck you Hacker!!"


@app.route('/clear/<passcode>')
def remove(passcode):  # 全部清理
    if clearcode == passcode:
        order = 'docker ps'
        ret = os.popen(order).read().split('\n')[1:]
        for cont in ret:
            if imageID in cont:
                aimID = cont[:12]
                os.popen(stopOrder.format(ID=aimID))
        return "Done!"
    else:
        return "Fvck you Hacker!!"


###########功能函数###################
def doDeply(username):  # 部署
    if username in containerDic.keys():
        port = containerDic[username][1]
        return "你已经部署过靶机了!,请访问: {url}".format(url=baseUrl+':'+str(port))
    choosePort = portList.pop()
    turl = baseUrl+':'+str(choosePort)
    containerSHA = os.popen(runOrder.format(
        port=choosePort, ID=imageID, inPort=innerPort)).read()
    containerDic[username] = [containerSHA, choosePort]
    return render_template("deploy.html", url=turl, info=containerSHA)


def doDestory(username):  # 销毁
    if username not in containerDic.keys():
        return "你没有正在运行的靶机"
    else:
        id = dropUser(username)
        stopContainer(id)
        return "销毁成功, 请重新生成靶机"


def dropUser(username):  # 接受一个username, 将其从containerDIC中移除, 将端口号push回未占用列表, 返回需要free的containerID
    container = containerDic[username]
    port = container[1]
    id = container[0]
    containerDic.pop(username)
    portList.add(port)
    return id


def stopContainer(id):
    try:
        os.popen(stopOrder.format(ID=id))
        return 1
    except:
        return 0


def check(user):  # 校验用户cookie是否合法
    if(user in userDic.keys()):
        passwd = userDic[user]
        if passwd == request.cookies.get('userpass'):  # 和用户的哈希校验
            return True
    return False


if __name__ == "__main__":
    subprocess.Popen(clearOrder.format(
        port=deployPort, uri='/container/', passcode=clearcode), shell=True)  # 拉起清理进程
    app.run(host='0.0.0.0', port=deployPort, debug=0)
