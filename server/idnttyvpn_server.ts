const serverPackage = require('./package.json');

const { codec } = require('lisk-sdk');
const { exec } = require("child_process");
const { Wg } = require('wireguard-wrapper');
const { apiClient } = require('@liskhq/lisk-client');
var http = require('http');


class IdnttyVPNServer {

    idnttyPublicKey = null;
    idnttyEndtpoint = null;
    idnttyNodeClient = null;
        
    interface = null;
    publicKey = null;    
    publicAddress = null;
    publicPort = null;
    addressRange = null;

    peers = [];

    constructor() {    
        this.idnttyPublicKey = serverPackage.idnttyPublicKey;
        this.idnttyEndtpoint = serverPackage.idnttyEndtpoint;        

        this.interface = serverPackage.interface;
        this.publicKey = serverPackage.publicKey;
        this.publicAddress = serverPackage.publicAddress;
        this.publicPort = serverPackage.publicPort;
        this.addressRange = serverPackage.addressRange;   
        this.peers = [];
    }

    load() {        
        apiClient.createWSClient(this.idnttyEndtpoint).then(async _client => {
            this.idnttyNodeClient = _client;

            this.idnttyNodeClient.subscribe('idnttyvpn:tunnel', (data) => {
                console.log(data);                                
            });  
            
            this.idnttyNodeClient.subscribe('app:block:new:tunnel', (data) => {                          
                _client.invoke('idnttyvpn:servers').then( async _servers => {    
                    console.log(_servers);        
                });                
            }); 
            
        });
    }

    unload() {        
        this.idnttyNodeClient.disconnect();
    }

    addVPNPeer(clientPublicKey, allowedIP) {
        exec(`sudo wg set ${this.interface} peer ${clientPublicKey} allowed-ips ${allowedIP}`, (error, stdout, stderr) => {
            if (error) { return false; }
            if (stderr) { return false; }            
            let peer = {
                publicKey: clientPublicKey,
                endpoint: null,
                allowedIps: allowedIP,
                latestHandshake: null,
                transferRx: null,
                transferTx: null,
            };
            this.peers.push(peer);
            return true;
        });
    }

    updatePublicIP() {
        http.get({'host': 'api.ipify.org', 'port': 80, 'path': '/'}, function(resp) {
            resp.on('data', function(ip) {
                this.publicAddress = ip;
            });
        });
    }

    updateVPNSettings() {
        let self = this;
        Wg.show(this.interface).then(async function(_interface) {
            self.publicPort = _interface[self.interface]['_listenPort'];
            self.idnttyPublicKey = _interface[self.interface]['_publicKey'];
        });
    }

    updateVPNPeers() {
        let self = this;
        Wg.show(this.interface).then(async function(_interface) {            
            self.peers = [];
            Object.keys(_interface[self.interface]['_peers']).forEach((_peer) => {
                let peer = {
                    publicKey: _peer,
                    endpoint: _interface[self.interface]['_peers'][_peer]["_endpoint"],
                    allowedIps: _interface[self.interface]['_peers'][_peer]["_allowedIps"],
                    latestHandshake: _interface[self.interface]['_peers'][_peer]["_latestHandshake"],
                    transferRx: _interface[self.interface]['_peers'][_peer]["_transferRx"],
                    transferTx: _interface[self.interface]['_peers'][_peer]["_transferTx"],
                };
                self.peers.push(peer);
            });                             
        });
    }

}


let vpn = new IdnttyVPNServer();
vpn.load();
setTimeout(function() { vpn.unload() }, 25000);
