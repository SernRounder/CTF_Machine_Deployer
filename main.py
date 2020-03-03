from flask import Flask, render_template, request, make_response
import hashlib
import os
import subprocess
import random
app=Flask(__name__)

baseUrl='base.sern.site'
imageID='ff0e54cff424'
innerPort=80
deployPort=5000
witerList=[]

runOrder='docker run -p {port}:{inPort} --rm -d {ID}'
stopOrder='docker stop {ID}'
clearOrder='python /home/rounder/flask/autoDeploy/helper.py {port} {uri} {passcode}'

userDic={}
startPort=6000
endPort=6666

clearcode=str(random.random())
portList=set(i for i in range(startPort,endPort))

containerDic={}
'''
{
    user:
    [containerID,port]
}
'''

@app.route('/register', methods=['GET', 'POST']) # 注册页面
def reg():
    user=request.args.get("name")
    if not user:# 用户名空
        return render_template("reg.html")
    passwd=request.args.get("passwd")
    if user not in userDic.keys(): # 新用户
        userDic[user]=passwd
    else:
        return "用户名冲突"
    return '注册成功, <a href="/"><button type="button">点此登录</button></a>'

@app.route("/") # 根目录
def root():
    user=request.cookies.get('username')
    if check(user): # cookies校验通过
        return render_template("user.html",user=user)
    return render_template("index.html") # 登录页面

@app.route('/deploy') # 部署验证
def deploy():
    user=request.cookies.get('username')
    if(check(user)):
            return doDeply(user)
    return "Die Hacker!!"

@app.route("/destory") # 销毁验证
def destory():
    user=request.cookies.get('username')
    if(check(user)):
        return doDestory(user)
    return "Die Hacker!!"

@app.route("/login",methods=['GET']) # 登录
def login():
    user=request.args.get("name")
    if not user:
        return '请输入正确的用户名<meta http-equiv="refresh" content="2;url=/">'
    passwd=request.args.get("passwd").encode('utf-8')
    if user in userDic.keys() and userDic[user].encode('utf-8')==passwd: 
            resp = make_response('<h1>登录成功</h1><meta http-equiv="refresh" content="2;url=/">') # 设置cookie
            md5hash = hashlib.md5(passwd)
            md5 = md5hash.hexdigest()
            resp.set_cookie('username', user)
            resp.set_cookie('userpass',md5)
            return resp
    else:
        return '用户名或密码错误<meta http-equiv="refresh" content="2;url=/">'


def doDeply(username): # 部署
    if username in containerDic.keys():
        port=containerDic[username][1]
        return "你已经部署过靶机了!,请访问: {url}".format(url=baseUrl+':'+str(port))
    choosePort=portList.pop()
    turl=baseUrl+':'+str(choosePort)
    containerSHA=os.popen(runOrder.format(port=choosePort,ID=imageID,inPort=innerPort)).read()
    containerDic[username]=[containerSHA,choosePort]
    return render_template("deploy.html",url=turl,info=containerSHA)

def doDestory(username): # 销毁
    if username not in containerDic.keys():
        return "你没有正在运行的靶机"
    else:
        container=containerDic[username]
        containerDic.pop(username)
        id=container[0]
        port=container[1]
        os.popen(stopOrder.format(ID=id))
        portList.add(port)
        return "销毁成功, 请重新生成靶机"
        
@app.route('/container/<passcode>')
def clear(passcode): # 自动清理
    if clearcode==passcode:
        order='docker ps'
        ret=os.popen(order).read().split('\n')[1:-3]
        for cont in ret:
            if 'hour' in cont:
                aimID=cont[:12]
                if aimID in witerList:
                    continue
                for user in containerDic:
                    if containerDic[user][0][:12]==aimID:
                        doDestory(user)
                        break
        return "Done!"
    else:
        return "Fvck you Hacker!!"

@app.route('/clear/<passcode>')
def remove(passcode): # 全部清理
    if clearcode==passcode:
        order='docker ps'
        ret=os.popen(order).read().split('\n')[1:-3]
        for cont in ret:
            if imageID in cont:
                aimID=cont[:12]
                os.popen(stopOrder.format(ID=aimID))
        return "Done!"
    else:
        return "Fvck you Hacker!!"

def check(user): # 校验用户cookie是否合法
    if(user in userDic.keys() ):
        passwd=userDic[user].encode('utf-8')
        md5hash = hashlib.md5(passwd)
        md5 = md5hash.hexdigest()
        if md5==request.cookies.get('userpass'):
            return True
    return False

if __name__ == "__main__":
    subprocess.Popen(clearOrder.format(port=deployPort,uri='/container/',passcode=clearcode),shell=True)
    app.run(host='0.0.0.0',port=deployPort,debug=0)
