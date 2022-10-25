const pluginPackage = require('./package.json');
const { apiClient } = require('@liskhq/lisk-client');
const { BasePlugin, BaseChannel, EventsDefinition, ActionsDefinition, SchemaWithDefault } = require("lisk-sdk");

import { createClient } from 'redis';
const sodium = require('sodium-native');

const DB_KEY_FAUCET = 'VPN:';

export class IdnttyVPNPlugin extends BasePlugin {        

    public name = pluginPackage.name;

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


    public get events(): EventsDefinition {
      return ['peeradd', 'peerremove'];
    }

    public get actions(): ActionsDefinition {
        return {
            servers: async ( ) => {
              return "pong:servers";
            },
            peer: async ( _peer: object ) => {
              console.log(_peer);
              return "pong:peer";
            },
        };
    }

    public async load(channel: BaseChannel): Promise<void> {

      this._channel = channel;

      this.db = createClient();
      this.db.on('error', (err) => console.log('Redis Client Error', err));                    
      await this.db.connect();

      this._channel.subscribe('app:block:new', (data) => {

        const decodedBlock = this.codec.decodeBlock(data.block);   

        decodedBlock.payload.forEach(blockTransaction => {
            blockTransaction.height = decodedBlock.header.height;
            console.log(blockTransaction.moduleID, blockTransaction.assetID);
            if (blockTransaction.moduleID == 1001 && blockTransaction.assetID == 1) { //some condition 
              let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
              sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(blockTransaction.senderPublicKey, 'hex'));
              this._channel.publish('idnttyvpn:addpeer', { publicKey : x25519_pk.toString('Base64') });
            }
        });        
      });

    }

    public async unload(): Promise<void> {}

}