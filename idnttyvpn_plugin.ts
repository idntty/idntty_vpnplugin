import { configSchema } from './schemas';

const pluginPackage = require('./package.json');
const { BasePlugin, BaseChannel, EventsDefinition, ActionsDefinition, SchemaWithDefault } = require("lisk-sdk");
const { getAddressFromPublicKey } = require('@liskhq/lisk-cryptography');


import { createClient } from 'redis';
const sodium = require('sodium-native');


//Tunnel
const DB_HASH_TUNNELS = 'TUNNELS';
const DB_HASH_TUNNEL = 'TUNNEL';
//Peers
const DB_HASH_PEERS = 'PEERS';
const DB_HASH_PEER = 'PEER';
//TX
const TX_MODULE_ID = 5;
const TX_ASSET_ID = 1;



export class IdnttyVPNPlugin extends BasePlugin {        
    public name = pluginPackage.name;
    private db;
    private heardbeat;

    public static get alias(): string {
	    return pluginPackage.name;
    }
    
    public static get info(): PluginInfo {
        return {
            author: pluginPackage.author,
            version: pluginPackage.version,
            name: pluginPackage.name,
        };
    }

    public get defaults(): SchemaWithDefault {
	    return configSchema;
    }

    public get events(): EventsDefinition {
      return ['peerAdd', 'peerRemove'];
    }

    public get actions(): ActionsDefinition {
        return {
            tunnelAdd: async ( _server: object ) => {              
              const status = await this._tunnelAdd(_server);
              return {status: status};
            },
            tunnelUpdateStatus: async (_server: object) => {
              const status = await this._tunnelUpdateStatus(_server);              
              return {status: status};
            },
            peerTunnels: async ( peer: object ) => {
              let tunnels = await this._peerTunnels(peer.publicKey);
              return tunnels;
            },
            peerConfirm: async ( peer: object ) => {
              let tunnels = await this._peerConfirm(peer);
              return tunnels;
            },
        };
    }

    public async load(channel: BaseChannel): Promise<void> {
      this._channel = channel;

      this.idnttyPublicKey = Buffer.from(this.options.publicKey, 'hex');
      this.idnttyAddress = getAddressFromPublicKey(this.idnttyPublicKey);
      this.serviceFee = this.options.serviceFee;
      this.heardbeat = 0;

      this._logger.debug({ address: this.idnttyAddress.toString('hex') }, 'IDNTTY VPN');

      this.setupDatabase(this.options.redisConnectionString);
      this._channel.subscribe('app:block:new', (data) => {
        this._accountVotes(data);

        this.heardbeat++;
        if (this.heardbeat % 13 == 0) {
          this._tunnelCheckStatus();
          this.heardbeat = 0;
          }
      });
    }

    public async unload(): Promise<void> {}

    private async setupDatabase(connectionString: string): Promise<void> {      
      this.db = createClient({ url: connectionString });
      this.db.on('error', (err) => this._logger.debug({ error: err }, 'Redis Client Error'));
      return this.db.connect();
    }

    private async _tunnelAdd(tunnel: object): Promise<boolean> {      
      const handshake = Date.now();
      const publicKey = tunnel.publicKey;

      let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
      sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(publicKey, 'hex'));

      tunnel.publicKey = x25519_pk.toString('Base64');
      tunnel.state = 1;

      this.db.hSet(DB_HASH_TUNNELS, {[publicKey]: handshake}).then(async () => {
        this.db.hSet(DB_HASH_TUNNEL.concat("::", publicKey), tunnel).then(async () => {
          
          let peers = await this.db.hGetAll(DB_HASH_PEERS);
          Object.keys(peers).forEach(async (peerPublicKey) => {
            this._peerAddtoTunnel(peerPublicKey, publicKey);
          });

          return true;
        });
      });
    }

    private async _tunnelUpdateStatus(tunnel: object): Promise<boolean> {
      const handshake = Date.now();
      const publicKey = tunnel.publicKey;

      let status = await this.db.hSet(DB_HASH_TUNNELS, {[publicKey]: handshake});
      //await this.db.hSet(DB_HASH_TUNNEL.concat("::", publicKey), {transferTx: tunnel.transferTx, transferRx: tunnel.transferRx});
      await this.db.hIncrBy(DB_HASH_TUNNEL.concat("::", publicKey), "transferTx", tunnel.transferTx);
      await this.db.hIncrBy(DB_HASH_TUNNEL.concat("::", publicKey), "transferRx", tunnel.transferRx);
      
      for await (const tunnelPeer of tunnel.peers) {
        this.db.hSet(DB_HASH_PEER.concat("::", tunnelPeer.publicKey, "::", tunnel.publicKey), {address:tunnelPeer.address, state: 1});
        this.db.hIncrBy(DB_HASH_PEER.concat("::", tunnelPeer.publicKey, "::", tunnel.publicKey), "transferTx", tunnelPeer.transferTx);
        this.db.hIncrBy(DB_HASH_PEER.concat("::", tunnelPeer.publicKey, "::", tunnel.publicKey), "transferRx", tunnelPeer.transferRx);

        this.db.hSet(DB_HASH_PEERS, {[tunnelPeer.publicKey]: tunnelPeer.latestHandshake});
      }
      

      /*
      const status = await this.db.hSet(DB_HASH_TUNNELS, {[publicKey]: handshake}).then(async () => {
        this.db.hSet(DB_HASH_TUNNEL.concat("::", publicKey), {transferTx: tunnel.transferTx, transferRx: tunnel.transferRx}).then(async () => {
          tunnel.peers.forEach(tunnelPeer => {
            this.db.hSet(DB_HASH_PEER.concat("::", tunnelPeer.publicKey, "::", tunnel.publicKey), {transferTx:tunnelPeer.transferTx, transferRx:tunnelPeer.transferRx, address:tunnelPeer.address, state: 1});
            this.db.hSet(DB_HASH_PEERS, {[tunnelPeer.publicKey]: tunnelPeer.latestHandshake});
          });        
        });
      });
      */

      return status === 0 ? true : false;
    }

    private async _tunnelCheckStatus(): Promise<void> {
      const handshake = Date.now();
      let tunnels = await this.db.hGetAll(DB_HASH_TUNNELS);
      Object.keys(tunnels).forEach(async (tunnelPublicKey) => {
          let lastHandshake = handshake - tunnels[tunnelPublicKey];
          this._logger.debug({ heartdeat: lastHandshake }, `IDNTTY VPN :: ${tunnelPublicKey} last handshake:`);
      });
    }

    private async _tunnelSuspend(tunnelPublicKey: string): Promise<boolean> {
      this.db.hdel(DB_HASH_TUNNELS, tunnelPublicKey ).then(async () => {
        this.db.del(DB_HASH_TUNNEL.concat("::", tunnelPublicKey)).then(async () => {
          for await (const key of this.db.scanIterator({TYPE: 'hash', MATCH: DB_HASH_PEER.concat("::", "*", "::", tunnelPublicKey)})) {            
            await this.db.hSet(key, {state:-1});            
          }          
        });
      });
    }

    private async _accountVotes(data: object): void {
      const decodedBlock = this.codec.decodeBlock(data.block);
      decodedBlock.payload.forEach((_tx) => {
        if (_tx.moduleID == TX_MODULE_ID && _tx.assetID == TX_ASSET_ID) {
          data.accounts.forEach((account) => {
            const decodedAccount = this.codec.decodeAccount(account);
            decodedAccount.dpos.sentVotes.forEach(async (vote) => {
              const delegateVote = Buffer.from(vote.delegateAddress, 'hex');              
              if ( Buffer.compare(delegateVote, this.idnttyAddress) === 0 && vote.amount/(10**8) >= this.serviceFee ) { this._peerAdd(_tx.senderPublicKey); } //Add peer              
              if ( Buffer.compare(delegateVote, this.idnttyAddress) === 0 && vote.amount/(10**8) < this.serviceFee ) { this._peerRemove(_tx.senderPublicKey);} //Remove peer
            });
          });
        }
      });
    }

    private async _peerAdd(peerPublicKey: string): Promise<void> {

      const handshake = Date.now();
      let _peerPublicKey = Buffer.from(peerPublicKey, 'hex');  
      let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
      sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, _peerPublicKey);                

      let tunnels = await this.db.hGetAll(DB_HASH_TUNNELS);
      Object.keys(tunnels).forEach(async (tunnelPublicKey) => {
          
          let tunnel = await this.db.hGetAll(DB_HASH_TUNNEL.concat("::", tunnelPublicKey));
          const tunnelObject = Object.assign({}, tunnel);

          let _peer = {
              peerPublicKey: x25519_pk.toString('Base64'),
              serverPublickKey: tunnelObject.publicKey,
              endpoint: tunnel.serverAddress.concat(":", tunnelObject.serverPort),
              region: tunnelObject.region,
              country: tunnelObject.county,
              transferTx: 0,
              transferRx: 0,
              state: 0
          }
  
          this.db.hSet(DB_HASH_PEERS, {[peerPublicKey]: handshake}).then(async () => {
            this.db.hSet(DB_HASH_PEER.concat("::", peerPublicKey, "::", tunnelPublicKey), _peer).then(async () => {
              this._channel.publish("idnttyvpn:peerAdd", {peerPublicKey:peerPublicKey, tunnelPublicKey:tunnelPublicKey});
              this._logger.debug({ publicKey: peerPublicKey }, 'IDNTTY VPN :: peer added');
            });
          });  
      });

    }

    private async _peerAddtoTunnel(peerPublicKey: string, tunnelPublicKey: string, ): Promise<void> {

      let _peerPublicKey = Buffer.from(peerPublicKey, 'hex');  
      let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
      sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, _peerPublicKey);                

      let tunnel = await this.db.hGetAll(DB_HASH_TUNNEL.concat("::", tunnelPublicKey));
      const tunnelObject = Object.assign({}, tunnel);

      let _peer = {
          peerPublicKey: x25519_pk.toString('Base64'),
          serverPublickKey: tunnelObject.publicKey,
          endpoint: tunnel.serverAddress.concat(":", tunnelObject.serverPort),
          region: tunnelObject.region,
          country: tunnelObject.county,
          transferTx: 0,
          transferRx: 0,
          state: 0
      }
      
      this.db.hSet(DB_HASH_PEER.concat("::", peerPublicKey, "::", tunnelPublicKey), _peer).then(async () => {
        this._channel.publish("idnttyvpn:peerAdd", {peerPublicKey:peerPublicKey, tunnelPublicKey:tunnelPublicKey});
        this._logger.debug({ publicKey: peerPublicKey }, 'IDNTTY VPN :: peer added');
      });

    }

    private async _peerRemove(peerPublicKey: string): Promise<void> {      
      this.db.hdel(DB_HASH_PEERS, peerPublicKey ).then(async () => {

        let tunnels = await this.db.hGetAll(DB_HASH_TUNNELS);
        Object.keys(tunnels).forEach(async (tunnelPublicKey) => {
            this.db.del(DB_HASH_PEER.concat("::", peerPublicKey, "::", tunnelPublicKey)).then(async () => {
              this._channel.publish("idnttyvpn:peerRemove", {peerPublicKey:peerPublicKey, tunnelPublicKey:tunnelPublicKey});
              this._logger.debug({ publicKey: peerPublicKey }, 'IDNTTY VPN :: peer removed');
            });
        });

      });      
    }

    private async _peerConfirm(peer: object): Promise<void> {
      let _peer = {
        state: 1,
        address: peer.address
      }
      this.db.hSet(DB_HASH_PEER.concat("::", peer.publicKey, "::", peer.tunnelPublicKey), _peer).then(async () => {
        this._logger.debug({ publicKey: peer.publicKey }, 'IDNTTY VPN :: peer confirmed');
      });
    }

    private async _peerTunnels(peerPublicKey: string): object[] {      
      let peers = [];
      for await (const key of this.db.scanIterator({TYPE: 'hash', MATCH: DB_HASH_PEER.concat("::", peerPublicKey, "::*")})) {
        let peer = await this.db.hGetAll(key);        
        const peerObject = Object.assign({},peer);        
        peers.push(peerObject);
      }
      return peers;
    }
    
}
