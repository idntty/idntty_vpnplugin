const pluginPackage = require('./package.json');

const { apiClient } = require('@liskhq/lisk-client');

const { BasePlugin, BaseChannel, EventsDefinition, ActionsDefinition, SchemaWithDefault } = require("lisk-sdk");
import { createClient } from 'redis';

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
      return ['tunnel'];
    }

    public get actions(): ActionsDefinition {
        return {
            servers: async ( ) => {              
              return "pong:servers";
            },
            getTunnels: async ( _user: object ) => {
              return "pong:getTunnels";
            },
            createTunnels: async ( _auth: object ) => {
              return "pong:createTunnels";
            },
            deleteTunnels: async ( _auth: object, tunnel: string) => {
              return "pong:deleteTunnels";
            },
        };
    }

    public async load(channel: BaseChannel): Promise<void> {

        this.db = createClient();
        this.db.on('error', (err) => console.log('Redis Client Error', err));                    
        await this.db.connect();

        this._channel.subscribe('app:block:new', (data) => {
          this._channel.publish('IdnttyVPNPlugin:tunnel', { some : "value" });
        });

    }

    public async unload(): Promise<void> {}

}