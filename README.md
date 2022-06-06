# k8s-controller-node


## Cloud lab 
These playbooks are run on a controller node to install k8s on a baremetal/VM cluster based on this post <https://linuxconfig.org/how-to-install-kubernetes-on-ubuntu-20-04-focal-fossa-linux>. After initialized with playbook, all hosts will have admin user and PK authentication.

hosts:
    user: admin
    nopw

## Keys
Change permission for key fiels in the keys folder.
    chmod 700 .ssh
    chmod 600 .ssh/authorized_keys
    chmod 600 keys/id*

## Usage

These playbooks are applied to Ubuntu 20.04 baremetals or VMs.

### Host group
Default host group is k8s-all. Set the --extra-vars "variable_hosts=newtargets" in ansible-playbook command to override it.

Update masters and workers nodes IP, root password in inventory file ./ansible/hosts.

#### Step 0 - Setup baremetal nodes
Make sure br_netfilter kernel module is loaded. Auto loaded in playbook.

    cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
    overlay
    br_netfilter
    EOF


1. Run playbook for user and keys:

     ansible-playbook --extra-vars "variable_hosts=k8s-all" ./playbooks/0_setup_baremetal.yml

2. Set hostname

     sudo hostnamectl set-hostname host_name
     sudo vim /etc/hosts

3. Disable UFW, Ubuntu firewall

     systemctl stop ufw
     systemctl disable ufw

4. Optional: Firewall rules. Run firewall.sh, check default net dev

#### Step 1 - Setup container backend

     ansible-playbook --extra-vars "variable_hosts=k8s-all" ./playbooks/1_1_setup_container.yml

#### Step 2 - Setup k8s 

     ansible-playbook --extra-vars "variable_hosts=k8s-all" ./playbooks/1_2_kube_dependencies.yml
     ansible-playbook --extra-vars "variable_hosts=k8s-all" ./playbooks/2_master.yml
     ansible-playbook --extra-vars "variable_hosts=k8s-all" ./playbooks/3_workers.yml

#### Step 3 - Test the setup

     ssh admin@master -i ../keys/id_rsa
     kubectl get nodes -o wide


## Tips

Rerun the playbook from tasks: use --start-at-task "name_string" to skip the preceeding tasks.


## Security
- https://gist.github.com/thuydang/68904d3b7699b000e3b0
- https://stackoverflow.com/questions/39293441/needed-ports-for-kubernetes-cluster

## History

20220523: installed k8s using playbooks.
