# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Detection Home Lab — Vagrantfile
# Hypervisor : VirtualBox
# Provisioner: Ansible (ansible_local — runs inside each VM, no Ansible on Windows host needed)
#
# Network layout (Host-Only: 192.168.56.0/24):
#   192.168.56.10  wazuh-server  — Wazuh 4.14 all-in-one (Manager + Indexer + Dashboard)
#   192.168.56.20  agent-node    — Sysmon4Linux + Wazuh Agent
#   192.168.56.30  attacker      — MITRE ATT&CK simulation scripts

WAZUH_SERVER_IP = "192.168.56.10"
AGENT_NODE_IP   = "192.168.56.20"
ATTACKER_IP     = "192.168.56.30"
VAGRANT_BOX     = "ubuntu/jammy64"  # Ubuntu 22.04 LTS

Vagrant.configure("2") do |config|

  # Shared synced folder: project root → /vagrant inside every VM
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  # ── VM 1: Wazuh Server (SIEM all-in-one) ────────────────────────────────
  config.vm.define "wazuh-server" do |srv|
    srv.vm.box      = VAGRANT_BOX
    srv.vm.hostname = "wazuh-server"
    srv.vm.network  "private_network", ip: WAZUH_SERVER_IP

    srv.vm.provider "virtualbox" do |vb|
      vb.name   = "DetectionLab-WazuhServer"
      vb.memory = 8192   # Wazuh Indexer (OpenSearch) is memory-hungry
      vb.cpus   = 4
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      vb.customize ["modifyvm", :id, "--natdnsproxy1",        "on"]
      # Increase disk I/O performance for Wazuh Indexer
      vb.customize ["storagectl", :id, "--name", "SCSI", "--hostiocache", "on"] rescue nil
    end

    srv.vm.provision "ansible_local" do |ansible|
      ansible.playbook       = "ansible/wazuh_server.yml"
      ansible.install_mode   = "default"
      ansible.version        = "latest"
      ansible.extra_vars     = {
        wazuh_manager_ip: WAZUH_SERVER_IP,
        wazuh_version:    "4.14"
      }
    end
  end

  # ── VM 2: Agent Node (monitored endpoint) ───────────────────────────────
  config.vm.define "agent-node" do |agent|
    agent.vm.box      = VAGRANT_BOX
    agent.vm.hostname = "agent-node"
    agent.vm.network  "private_network", ip: AGENT_NODE_IP

    agent.vm.provider "virtualbox" do |vb|
      vb.name   = "DetectionLab-AgentNode"
      vb.memory = 2048
      vb.cpus   = 2
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    end

    agent.vm.provision "ansible_local" do |ansible|
      ansible.playbook     = "ansible/agent_node.yml"
      ansible.install_mode = "default"
      ansible.version      = "latest"
      ansible.extra_vars   = {
        wazuh_manager_ip: WAZUH_SERVER_IP,
        wazuh_version:    "4.14"
      }
    end
  end

  # ── VM 3: Attacker Node ──────────────────────────────────────────────────
  config.vm.define "attacker" do |atk|
    atk.vm.box      = VAGRANT_BOX
    atk.vm.hostname = "attacker"
    atk.vm.network  "private_network", ip: ATTACKER_IP

    atk.vm.provider "virtualbox" do |vb|
      vb.name   = "DetectionLab-Attacker"
      vb.memory = 1024
      vb.cpus   = 1
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    end

    atk.vm.provision "ansible_local" do |ansible|
      ansible.playbook     = "ansible/attacker.yml"
      ansible.install_mode = "default"
      ansible.version      = "latest"
      ansible.extra_vars   = {
        agent_node_ip: AGENT_NODE_IP
      }
    end
  end

end
