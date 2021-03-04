# 虚拟机选择
* Win10 Hyper-V

# 总体架构

三个master，三个node

## master的组件
* etcd
* kube-apiserver
* kube-controller-manager
* kube-scheduler
* kubelet
* kube-proxy
* docker
* nginx

## node组件
* kubelet
* kube-proxy
* docker
* nginx

# 环境准备
> 在所有节点操作

## 所有主机统一hosts
```
cat /etc/hosts

127.0.0.1 apiserver.k8s.local
192.168.31.21 master01
192.168.31.22 master02
192.168.31.23 master03
192.168.31.24 node01
192.168.31.25 node02
192.168.31.26 node03

```
## 设置主机名
```
hostnamectl set-hostname NAME
```

## 硬件配置
|IP      |HostName       |内核     |CPU    |Memory   |
|---------|--------------|--------|-----------|----------|
|192.168.31.21   |master01        |3.10.0-1062      |2     |4G     |
|192.168.31.22   |master02        |3.10.0-1062      |2     |4G     |
|192.168.31.23   |master03        |3.10.0-1062      |2     |4G     |
|192.168.31.24   |node01          |3.10.0-1062      |2     |4G     |
|192.168.31.25   |node02          |3.10.0-1062      |2     |4G     |
|192.168.31.26   |node03          |3.10.0-1062      |2     |4G     |

* kubeadm好像要求最低配置2c2g还是多少来着，越高越好
* 所有操作全部用root使用者进行，系统盘根目录一定要大，不然到时候镜像多了例如到了85%会被gc回收镜像
* 高可用一般建议大于等于3台的奇数台,使用3台master来做高可用

## 所有机器升级内核（可选）
> 导入升级内核的yum源

```
rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
```

> 查看可用版本 kernel-lt指长期稳定版 kernel-ml指最新版

```
yum --disablerepo="*" --enablerepo="elrepo-kernel" list available
```

> 安装kernel-ml

```
yum --enablerepo=elrepo-kernel install kernel-ml kernel-ml-devel -y
```

### 设置启动项
> 查看系统上的所有可用内核

```
awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg
```

> 设置新的内核为grub2的默认版本

```text
grub2-set-default 'CentOS Linux (5.7.7-1.el7.elrepo.x86_64) 7 (Core)'
```

> 生成 grub 配置文件并重启

```text
grub2-mkconfig -o /boot/grub2/grub.cfg

reboot
```

## 所有机器都关闭防火墙，swap，selinux

```text
#关闭防火墙
systemctl disable --now firewalld

#关闭swap
swapoff -a
sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab

#关闭selinux
setenforce 0
sed -ri '/^[^#]*SELINUX=/s#=.+$#=disabled#' /etc/selinux/config
```

## 所有机器yum

```text
yum install epel-release -y

yum update -y
```

```text
yum -y install  gcc bc gcc-c++ ncurses ncurses-devel cmake elfutils-libelf-devel openssl-devel flex* bison* autoconf automake zlib* fiex* libxml* ncurses-devel libmcrypt* libtool-ltdl-devel* make cmake  pcre pcre-devel openssl openssl-devel   jemalloc-devel tlc libtool vim unzip wget lrzsz bash-comp* ipvsadm ipset jq sysstat conntrack libseccomp conntrack-tools socat curl wget git conntrack-tools psmisc nfs-utils tree bash-completion conntrack libseccomp net-tools crontabs sysstat iftop nload strace bind-utils tcpdump htop telnet lsof
```

> 所有机器都加载ipvs

```text
cat > /etc/modules-load.d/ipvs.conf <<EOF
module=(
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
nf_conntrack
nf_conntrack_ipv4
br_netfilter
  )
for kernel_module in ${module[@]};do
    /sbin/modinfo -F filename $kernel_module |& grep -qv ERROR && echo $kernel_module >> /etc/modules-load.d/ipvs.conf || :
done
EOF
```

> 加载ipvs模块

```text
systemctl daemon-reload
source  /etc/modules-load.d/ipvs.conf
```

> 查询ipvs是否加载

```text
$ lsmod | grep ip_vs
ip_vs_sh               12688  0 
ip_vs_wrr              12697  0 
ip_vs_rr               12600  11 
ip_vs                 145497  17 ip_vs_rr,ip_vs_sh,ip_vs_wrr
nf_conntrack          133095  7 ip_vs,nf_nat,nf_nat_ipv4,xt_conntrack,nf_nat_masquerade_ipv4,nf_conntrack_netlink,nf_conntrack_ipv4
libcrc32c              12644  3 ip_vs,nf_nat,nf_conntrack
```

## 所有机器都设置k8s系统参数

```text
cat <<EOF > /etc/sysctl.d/k8s.conf
net.ipv6.conf.all.disable_ipv6 = 1           #禁用ipv6
net.ipv6.conf.default.disable_ipv6 = 1       #禁用ipv6
net.ipv6.conf.lo.disable_ipv6 = 1            #禁用ipv6
net.ipv4.neigh.default.gc_stale_time = 120   #决定检查过期多久邻居条目
net.ipv4.conf.all.rp_filter = 0              #关闭反向路由校验
net.ipv4.conf.default.rp_filter = 0          #关闭反向路由校验
net.ipv4.conf.default.arp_announce = 2       #始终使用与目标IP地址对应的最佳本地IP地址作为ARP请求的源IP地址
net.ipv4.conf.lo.arp_announce = 2            #始终使用与目标IP地址对应的最佳本地IP地址作为ARP请求的源IP地址
net.ipv4.conf.all.arp_announce = 2           #始终使用与目标IP地址对应的最佳本地IP地址作为ARP请求的源IP地址
net.ipv4.ip_forward = 1                      #启用ip转发功能
net.ipv4.tcp_max_tw_buckets = 5000           #表示系统同时保持TIME_WAIT套接字的最大数量
net.ipv4.tcp_syncookies = 1                  #表示开启SYN Cookies。当出现SYN等待队列溢出时，启用cookies来处理
net.ipv4.tcp_max_syn_backlog = 1024          #接受SYN同包的最大客户端数量
net.ipv4.tcp_synack_retries = 2              #活动TCP连接重传次数
net.bridge.bridge-nf-call-ip6tables = 1      #要求iptables对bridge的数据进行处理
net.bridge.bridge-nf-call-iptables = 1       #要求iptables对bridge的数据进行处理
net.bridge.bridge-nf-call-arptables = 1      #要求iptables对bridge的数据进行处理
net.netfilter.nf_conntrack_max = 2310720     #修改最大连接数
fs.inotify.max_user_watches=89100            #同一用户同时可以添加的watch数目
fs.may_detach_mounts = 1                     #允许文件卸载
fs.file-max = 52706963                       #系统级别的能够打开的文件句柄的数量
fs.nr_open = 52706963                        #单个进程可分配的最大文件数
vm.overcommit_memory=1                       #表示内核允许分配所有的物理内存，而不管当前的内存状态如何
vm.panic_on_oom=0                            #内核将检查是否有足够的可用内存供应用进程使用
vm.swappiness = 0                            #关注swap
net.ipv4.tcp_keepalive_time = 600            #修复ipvs模式下长连接timeout问题,小于900即可
net.ipv4.tcp_keepalive_intvl = 30            #探测没有确认时，重新发送探测的频度
net.ipv4.tcp_keepalive_probes = 10      升级内核（     #在认定连接失效之前，发送多少个TCP的keepalive探测包
vm.max_map_count=524288                      #定义了一个进程能拥有的最多的内存区域
EOF

sysctl --system
```

## 所有机器都设置文件最大数

```text
cat>/etc/security/limits.d/kubernetes.conf<<EOF
*       soft    nproc   131072
*       hard    nproc   131072
*       soft    nofile  131072
*       hard    nofile  131072
root    soft    nproc   131072
root    hard    nproc   131072
root    soft    nofile  131072
root    hard    nofile  131072
EOF
```

## 所有机器都设置docker 安装
> docker yum
```text
wget -P /etc/yum.repos.d/  https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
```

> 官方脚本检查

```text
grubby --args="user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"

#然后重启
reboot
```

> docker安装

```text
yum install docker-ce -y
```

> 配置docker

```text
cp /usr/share/bash-completion/completions/docker /etc/bash_completion.d/

mkdir -p /etc/docker/

cat > /etc/docker/daemon.json <<EOF
{
    "log-driver": "json-file",
    "exec-opts": ["native.cgroupdriver=systemd"],
    "log-opts": {
    "max-size": "100m",
    "max-file": "3"
    },
    "live-restore": true,
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 10,
    "registry-mirrors": ["https://2lefsjdg.mirror.aliyuncs.com"],
    "storage-driver": "overlay2",
    "storage-opts": [
    "overlay2.override_kernel_check=true"
    ]
}
EOF
```

> 启动docker

```text
systemctl enable --now docker
```

# kubeadm部署
## 所有机器都设置kubeadm yum
> 在所有节点操作

```text
cat <<EOF >/etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=0
EOF
```

> maser节点安装
```text
yum install -y \
    kubeadm-1.18.2 \
    kubectl-1.18.2 \
    kubelet-1.18.2 \
    --disableexcludes=kubernetes && \
    systemctl enable kubelet
```

> node节点安装
```text
yum install -y \
    kubeadm-1.18.2 \
    kubelet-1.18.2 \
    --disableexcludes=kubernetes && \
    systemctl enable kubelet
```

> master高可用

```text
mkdir -p /etc/kubernetes

cat > /etc/kubernetes/nginx.conf << EOF
error_log stderr notice;

worker_processes 2;
worker_rlimit_nofile 130048;
worker_shutdown_timeout 10s;

events {
  multi_accept on;
  use epoll;
  worker_connections 16384;
}

stream {
  upstream kube_apiserver {
    least_conn;
    server master01:6443;
    server master02:6443;
    server master03:6443;
    }

  server {
    listen        8443;
    proxy_pass    kube_apiserver;
    proxy_timeout 10m;
    proxy_connect_timeout 1s;
  }
}

http {
  aio threads;
  aio_write on;
  tcp_nopush on;
  tcp_nodelay on;

  keepalive_timeout 5m;
  keepalive_requests 100;
  reset_timedout_connection on;
  server_tokens off;
  autoindex off;

  server {
    listen 8081;
    location /healthz {
      access_log off;
      return 200;
    }
    location /stub_status {
      stub_status on;
      access_log off;
    }
  }
}
EOF
```

```text
docker run --restart=always \
    -v /etc/kubernetes/nginx.conf:/etc/nginx/nginx.conf \
    -v /etc/localtime:/etc/localtime:ro \
    --name k8sHA \
    --net host \
    -d \
    nginx
```

## kubeadm配置文件
> 在master01节点操作
```text
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
imageRepository: registry.cn-hangzhou.aliyuncs.com/k8sxio
kubernetesVersion: v1.18.2
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
networking: 
  dnsDomain: cluster.local
  serviceSubnet: 10.96.0.0/12
  podSubnet: 10.244.0.0/16
controlPlaneEndpoint: apiserver.k8s.local:8443
apiServer:
  timeoutForControlPlane: 4m0s
  extraArgs:
    authorization-mode: "Node,RBAC"
    enable-admission-plugins: "NamespaceLifecycle,LimitRanger,ServiceAccount,PersistentVolumeClaimResize,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,Priority,PodPreset"
    runtime-config: api/all=true,settings.k8s.io/v1alpha1=true
    storage-backend: etcd3
    etcd-servers: https://192.168.31.21:2379,https://192.168.31.22:2379,https://192.168.31.23:2379 #修改对应的ip
  certSANs:
  - 10.96.0.1
  - 127.0.0.1
  - localhost
  - apiserver.k8s.local
  - 192.168.31.21   #修改对应的ip
  - 192.168.31.22   #修改对应的ip
  - 192.168.31.23   #修改对应的ip
  - master01       #修改对应的hostname
  - master02       #修改对应的hostname
  - master03       #修改对应的hostname
  - master
  - kubernetes
  - kubernetes.default 
  - kubernetes.default.svc 
  - kubernetes.default.svc.cluster.local
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
controllerManager:
  extraArgs:
    bind-address: "0.0.0.0"
    experimental-cluster-signing-duration: 867000h
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
scheduler: 
  extraArgs:
    bind-address: "0.0.0.0"
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
dns:
  type: CoreDNS
  imageRepository: registry.aliyuncs.com/k8sxio
  imageTag: 1.6.7
etcd:
  local:
    imageRepository: registry.aliyuncs.com/k8sxio
    imageTag: 3.4.3-0
    dataDir: /var/lib/etcd
    serverCertSANs:
    - master
    - 192.168.31.21   #修改对应的ip
    - 192.168.31.22   #修改对应的ip
    - 192.168.31.23   #修改对应的ip
    - master01      #修改对应的hostname
    - master02      #修改对应的hostname
    - master03      #修改对应的hostname
    peerCertSANs:
    - master
    - 192.168.31.21   #修改对应的ip
    - 192.168.31.22   #修改对应的ip
    - 192.168.31.23   #修改对应的ip
    - master01           #修改对应的hostname
    - master02           #修改对应的hostname
    - master03           #修改对应的hostname
    extraArgs:
      auto-compaction-retention: "1h"
      max-request-bytes: "33554432"
      quota-backend-bytes: "8589934592"
      enable-v2: "false"
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
ipvs:
  excludeCIDRs: null
  minSyncPeriod: 0s
  scheduler: "rr"
  strictARP: false
  syncPeriod: 15s
iptables:
  masqueradeAll: true
  masqueradeBit: 14
  minSyncPeriod: 0s
  syncPeriod: 30s
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: "systemd"
failSwapOn: true
```

> 检查文件是否错误，忽略warning，错误的话会抛出error，没错则会输出到包含字符串kubeadm join xxx啥的
```text
kubeadm init --config /root/initconfig.yaml --dry-run
```

> 预先拉取镜像
```text
kubeadm config images pull --config /root/initconfig.yaml
```

## 部署master
> 在master01节点操作
```text
kubeadm init --config /root/initconfig.yaml --upload-certs

...
...
...
You can now join any number of the control-plane node running the following command on each as root:

  kubeadm join apiserver.k8s.local:8443 --token 8lmdqu.cqe8r0rxa0056vmm \
    --discovery-token-ca-cert-hash sha256:5ca87fff6b414a0872ab5452972d7e36e4bad7ab3a0bc385abe0138ce671eabb \
    --control-plane --certificate-key 7a1d432b2834464a82fd7cba0e9e5d8409c492cf9a4ee6328fb4f84b6a78934a

Please note that the certificate-key gives access to cluster sensitive data, keep it secret!
As a safeguard, uploaded-certs will be deleted in two hours; If necessary, you can use 
"kubeadm init phase upload-certs --upload-certs" to reload certs afterward.

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join apiserver.k8s.local:8443 --token 8lmdqu.cqe8r0rxa0056vmm \
    --discovery-token-ca-cert-hash sha256:5ca87fff6b414a0872ab5452972d7e36e4bad7ab3a0bc385abe0138ce671eabb
```

> 复制kubectl的kubeconfig，kubectl的kubeconfig路径默认是~/.kube/config
```text
mkdir -p $HOME/.kube

sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config

sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

> init的yaml信息实际上会存在集群的configmap里，我们可以随时查看，该yaml在其他node和master join的时候会使用到
```text
kubectl -n kube-system get cm kubeadm-config -o yaml
```

### 设置ep的rbac
> kube-apiserver的web健康检查路由有权限，我们需要开放用来监控或者对接SLB的健康检查

```text
cat > /root/healthz-rbac.yml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: healthz-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: healthz-reader
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:authenticated
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:unauthenticated
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: healthz-reader
rules:
- nonResourceURLs: ["/healthz", "/healthz/*"]
  verbs: ["get", "post"]
EOF
```

```text
kubectl apply -f /root/healthz-rbac.yml
```

### 配置其他master的k8s管理组件
> 将master01上的配置文件发到其他2个master节点上
```text
for node in 192.168.31.22 192.168.31.23;do
    ssh $node 'mkdir -p /etc/kubernetes/pki/etcd'
    scp -r /root/initconfig.yaml $node:/root/initconfig.yaml
    scp -r /etc/kubernetes/pki/ca.* $node:/etc/kubernetes/pki/
    scp -r /etc/kubernetes/pki/sa.* $node:/etc/kubernetes/pki/
    scp -r /etc/kubernetes/pki/front-proxy-ca.* $node:/etc/kubernetes/pki/
    scp -r /etc/kubernetes/pki/etcd/ca.* $node:/etc/kubernetes/pki/etcd/
done
```

### 其他master join进来
> 先拉取镜像
```text
kubeadm config images pull --config /root/initconfig.yaml
```

> 查看master01上 带有--control-plane的那一行
```text
kubeadm join apiserver.k8s.local:8443 --token 8lmdqu.cqe8r0rxa0056vmm \
    --discovery-token-ca-cert-hash sha256:5ca87fff6b414a0872ab5452972d7e36e4bad7ab3a0bc385abe0138ce671eabb \
    --control-plane --certificate-key 7a1d432b2834464a82fd7cba0e9e5d8409c492cf9a4ee6328fb4f84b6a78934a
```

### 所有master配置kubectl
> 准备kubectl的kubeconfig
```text
mkdir -p $HOME/.kube

sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config

sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

> 设置kubectl的补全脚本
```text
yum -y install bash-comp*

source <(kubectl completion bash)

echo 'source <(kubectl completion bash)' >> ~/.bashrc
```

#### master配置etcdctl
> 所有master节点先复制出容器里的etcdctl
```text
docker cp `docker ps -a | awk '/k8s_etcd/{print $1}'|head -n1`:/usr/local/bin/etcdctl /usr/local/bin/etcdctl
```

> 编写一个简单别名，记得替换对应的ip
```text
cat >/etc/profile.d/etcd.sh<<'EOF'
ETCD_CERET_DIR=/etc/kubernetes/pki/etcd/
ETCD_CA_FILE=ca.crt
ETCD_KEY_FILE=healthcheck-client.key
ETCD_CERT_FILE=healthcheck-client.crt
ETCD_EP=https://192.168.33.101:2379,https://192.168.33.102:2379,https://192.168.33.103:2379

alias etcd_v3="ETCDCTL_API=3 \
    etcdctl   \
   --cert ${ETCD_CERET_DIR}/${ETCD_CERT_FILE} \
   --key ${ETCD_CERET_DIR}/${ETCD_KEY_FILE} \
   --cacert ${ETCD_CERET_DIR}/${ETCD_CA_FILE} \
   --endpoints $ETCD_EP"
EOF
```

```text
source  /etc/profile.d/etcd.sh
```

```text
etcd_v3 endpoint status --write-out=table

+-----------------------------+------------------+---------+---------+-----------+-----------+------------+
|          ENDPOINT           |        ID        | VERSION | DB SIZE | IS LEADER | RAFT TERM | RAFT INDEX |
+-----------------------------+------------------+---------+---------+-----------+-----------+------------+
| https://192.168.31.21:2379 | c724c500884441af |  3.4.3  |  1.6 MB |      true |         7 |       1865 |
| https://192.168.31.22:2379 | 3dcceec24ad5c5d4 |  3.4.3  |  1.6 MB |     false |         7 |       1865 |
| https://192.168.31.23:2379 | bc21062efb4a5d4c |  3.4.3  |  1.5 MB |     false |         7 |       1865 |
+-----------------------------+------------------+---------+---------+-----------+-----------+------------+
```

```text
etcd_v3 endpoint health --write-out=table

+-----------------------------+--------+-------------+-------+
|          ENDPOINT           | HEALTH |    TOOK     | ERROR |
+-----------------------------+--------+-------------+-------+
| https://192.168.31.23:2379 |   true | 19.288026ms |       |
| https://192.168.31.22:2379 |   true |   19.2603ms |       |
| https://192.168.31.21:2379 |   true | 22.490443ms |       |
+-----------------------------+--------+-------------+-------+
```

## 部署node
> 在node节点执行
> 和master的join一样，提前准备好环境和docker，然后join的时候不需要带--control-plane

```text
kubeadm join apiserver.k8s.local:8443 --token 8lmdqu.cqe8r0rxa0056vmm \
    --discovery-token-ca-cert-hash sha256:5ca87fff6b414a0872ab5452972d7e36e4bad7ab3a0bc385abe0138ce671eabb
```

## 打标签
> role只是一个label，可以打label，想显示啥就`node-role.kubernetes.io/xxxx`

```text
[root@master01 ~]# kubectl get nodes
NAME       STATUS     ROLES    AGE   VERSION
master01   NotReady   master   17m   v1.18.2
master02   NotReady   master   14m   v1.18.2
master03   NotReady   master   13m   v1.18.2
node01     NotReady   <none>   24s   v1.18.2
node02     NotReady   <none>   18s   v1.18.2
node03     NotReady   <none>   11s   v1.18.2
```

```text
[root@master01 ~]# kubectl label node node01 node-role.kubernetes.io/node=""
node/node01 labeled
[root@master01 ~]# kubectl label node node02 node-role.kubernetes.io/node=""
node/node02 labeled
[root@master01 ~]# kubectl label node node03 node-role.kubernetes.io/node=""
node/node03 labeled

[root@master01 ~]# kubectl get nodes 
NAME       STATUS     ROLES    AGE     VERSION
master01   NotReady   master   25m     v1.18.2
master02   NotReady   master   22m     v1.18.2
master03   NotReady   master   21m     v1.18.2
node01     NotReady   node     8m      v1.18.2
node02     NotReady   node     7m54s   v1.18.2
node03     NotReady   node     7m47s   v1.18.2
```

# 部署网络插件Calico
> 没有网络插件，所有节点都是notready
> 在master01上操作

```text
https://docs.projectcalico.org/v3.11/manifests/calico.yaml
```

```text
sed -i -e "s?192.168.0.0/16?10.244.0.0/16?g" calico.yaml
```

```text
kubectl apply -f calico.yaml
```

# 测试
## 验证集群可用性
> 最基本的3master3node集群搭建完成了，必须有
* 3个 kube-apiserver
* 3个 kube-controller-manager
* 3个 kube-scheduler
* 3个 etcd
* 6个 kube-proxy
* 6个 calico-node
* 1个 calico-kube-controllers
* 2个 core-dns

```text
kubectl get pods --all-namespaces

NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
kube-system   calico-kube-controllers-648f4868b8-6pcqf   1/1     Running   0          2m10s
kube-system   calico-node-d4hqw                          1/1     Running   0          2m10s
kube-system   calico-node-glmcl                          1/1     Running   0          2m10s
kube-system   calico-node-qm8zz                          1/1     Running   0          2m10s
kube-system   calico-node-s64r9                          1/1     Running   0          2m10s
kube-system   calico-node-shxhv                          1/1     Running   0          2m10s
kube-system   calico-node-zx7nw                          1/1     Running   0          2m10s
kube-system   coredns-7b8f8b6cf6-kh22h                   1/1     Running   0          14m
kube-system   coredns-7b8f8b6cf6-vp9x6                   1/1     Running   0          14m
kube-system   etcd-master01                              1/1     Running   0          35m
kube-system   etcd-master02                              1/1     Running   0          33m
kube-system   etcd-master03                              1/1     Running   0          32m
kube-system   kube-apiserver-master01                    1/1     Running   0          35m
kube-system   kube-apiserver-master02                    1/1     Running   0          33m
kube-system   kube-apiserver-master03                    1/1     Running   0          31m
kube-system   kube-controller-manager-master01           1/1     Running   1          34m
kube-system   kube-controller-manager-master02           1/1     Running   0          33m
kube-system   kube-controller-manager-master03           1/1     Running   0          31m
kube-system   kube-proxy-2zbx4                           1/1     Running   0          32m
kube-system   kube-proxy-bbvqk                           1/1     Running   0          19m
kube-system   kube-proxy-j8899                           1/1     Running   0          33m
kube-system   kube-proxy-khrw5                           1/1     Running   0          19m
kube-system   kube-proxy-srpz9                           1/1     Running   0          19m
kube-system   kube-proxy-tz24q                           1/1     Running   0          36m
kube-system   kube-scheduler-master01                    1/1     Running   1          35m
kube-system   kube-scheduler-master02                    1/1     Running   0          33m
kube-system   kube-scheduler-master03                    1/1     Running   0          31m
 
```

## 重启docker，kubelet
> 由于kubeadm默认使用cgoupfs，官方推荐用systemd，所有节点都得进行检查和修改成systemd，然后重启docker，kubelelt
```text
vim /var/lib/kubelet/kubeadm-flags.env

KUBELET_KUBEADM_ARGS="--cgroup-driver=systemd --network-plugin=cni --pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/k8sxio/pause:3.2"
```
```text
vim /etc/docker/daemon.json

{
    "log-driver": "json-file",
    "exec-opts": ["native.cgroupdriver=systemd"],
    "log-opts": {
    "max-size": "100m",
    "max-file": "3"
    },
    "live-restore": true,
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 10,
    "registry-mirrors": ["https://2lefsjdg.mirror.aliyuncs.com"],
    "storage-driver": "overlay2",
    "storage-opts": [
    "overlay2.override_kernel_check=true"
    ]
}
```

> 所有节点先重启docker 再重启kubelet
```text
systemctl restart docker
systemctl restart kubelet
```
```text
[root@master01 ~]# kubectl get  nodes
NAME       STATUS   ROLES    AGE   VERSION
master01   Ready    master   37m   v1.18.2
master02   Ready    master   34m   v1.18.2
master03   Ready    master   33m   v1.18.2
node01     Ready    node     19m   v1.18.2
node02     Ready    node     19m   v1.18.2
node03     Ready    node     19m   v1.18.2
```
## demo测试
```text
cat<<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx:alpine
        name: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
spec:
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
  - name: busybox
    image: busybox:1.28.4
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
  restartPolicy: Always
EOF
```

```text
[root@master01 ~]# kubectl get all  -o wide
NAME                         READY   STATUS    RESTARTS   AGE   IP               NODE     NOMINATED NODE   READINESS GATES
pod/busybox                  1/1     Running   0          73s   10.244.186.194   node03   <none>           <none>
pod/nginx-5c559d5697-24zck   1/1     Running   0          73s   10.244.186.193   node03   <none>           <none>

NAME                 TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE   SELECTOR
service/kubernetes   ClusterIP   10.96.0.1      <none>        443/TCP   42m   <none>
service/nginx        ClusterIP   10.111.219.3   <none>        80/TCP    73s   app=nginx

NAME                    READY   UP-TO-DATE   AVAILABLE   AGE   CONTAINERS   IMAGES         SELECTOR
deployment.apps/nginx   1/1     1            1           73s   nginx        nginx:alpine   app=nginx

NAME                               DESIRED   CURRENT   READY   AGE   CONTAINERS   IMAGES         SELECTOR
replicaset.apps/nginx-5c559d5697   1         1         1       73s   nginx        nginx:alpine   app=nginx,pod-template-hash=5c559d5697
```

## 验证集群dns
```text
[root@master01 ~]# kubectl exec -ti busybox -- nslookup kubernetes
Server:   10.96.0.10
Address:  10.96.0.10#53

Name: kubernetes.default.svc.cluster.local
Address: 10.96.0.1
```

## 测试nginx是否通
> 在master上curl nginx的pod的ip出现nginx的index内容即集群正常
```text
[root@master01 ~]# curl 10.244.186.193
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

> 在master上curl nginx的svc的ip出现nginx的index内容即集群正常

```text
[root@master01 ~]# curl 10.111.219.3
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

```text
[root@master01 ~]# kubectl exec -ti busybox -- nslookup nginx
Server:   10.96.0.10
Address:  10.96.0.10#53

Name: nginx.default.svc.cluster.local
Address: 10.111.219.3
```

## ipvs验证
```text
[root@node01 ~]# ipvsadm -ln
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.96.0.1:443 rr
  -> 192.168.33.101:6443          Masq    1      1          0         
  -> 192.168.33.102:6443          Masq    1      0          0         
  -> 192.168.33.103:6443          Masq    1      1          0         
TCP  10.96.0.10:53 rr
  -> 10.244.140.65:53             Masq    1      0          0         
  -> 10.244.140.67:53             Masq    1      0          0         
TCP  10.96.0.10:9153 rr
  -> 10.244.140.65:9153           Masq    1      0          0         
  -> 10.244.140.67:9153           Masq    1      0          0         
TCP  10.111.219.3:80 rr
  -> 10.244.186.193:80            Masq    1      0          0         
UDP  10.96.0.10:53 rr
  -> 10.244.140.65:53             Masq    1      0          0         
  -> 10.244.140.67:53             Masq    1      0          0
```

# 搭建Dashboard
## 下载yaml文件
[https://github.com/w3liu/k8s/tree/main/dashboard](https://github.com/w3liu/k8s/tree/main/dashboard)

## 执行
```text
kubectl appy -f admin-user.yaml
kubectl appy -f admin-user-role-binding.yaml
kubectl appy -f dashboard-deployment.yaml
```

## 通过API Server访问
> 如果Kubernetes API服务器是公开的，并可以从外部访问，那我们可以直接使用API Server的方式来访问，也是比较推荐的方式。
> Dashboard的访问地址为：
```text
https://192.168.31.21:6443/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#/login
```
> 但是返回的结果可能如下：
```text
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "services \"https:kubernetes-dashboard:\" is forbidden: User \"system:anonymous\" cannot get services/proxy in the namespace \"kube-system\"",
  "reason": "Forbidden",
  "details": {
    "name": "https:kubernetes-dashboard:",
    "kind": "services"
  },
  "code": 403
}
```
> 这是因为最新版的k8s默认启用了RBAC，并为未认证用户赋予了一个默认的身份：anonymous。
> 对于API Server来说，它是使用证书进行认证的，我们需要先创建一个证书：
> 1.首先找到kubectl命令的配置文件，默认情况下为/etc/kubernetes/admin.conf，在 上一篇 中，我们已经复制到了$HOME/.kube/config中。 
> 2.然后我们使用client-certificate-data和client-key-data生成一个p12文件，可使用下列命令：
```text
# 生成client-certificate-data
grep 'client-certificate-data' ~/.kube/config | head -n 1 | awk '{print $2}' | base64 -d >> kubecfg.crt

# 生成client-key-data
grep 'client-key-data' ~/.kube/config | head -n 1 | awk '{print $2}' | base64 -d >> kubecfg.key

# 生成p12
openssl pkcs12 -export -clcerts -inkey kubecfg.key -in kubecfg.crt -out kubecfg.p12 -name "kubernetes-client"
```
> 3.最后导入上面生成的p12文件，关闭浏览器并重新打开即可

# 搭建Metrics-Server
## 下载yaml文件
[https://github.com/w3liu/k8s/tree/main/metrics-server](https://github.com/w3liu/k8s/tree/main/metrics-server)

## 执行
```text
kubectl appy -f components.yaml
```

# 参考文献
1. [https://www.jianshu.com/p/7ad86c485f49](https://www.jianshu.com/p/7ad86c485f49)
2. [https://www.yuque.com/xiaowei-trt7k/tw/usx3v0](https://www.yuque.com/xiaowei-trt7k/tw/usx3v0)
3. [https://www.cnblogs.com/danhuang/p/12617745.html](https://www.cnblogs.com/danhuang/p/12617745.html)