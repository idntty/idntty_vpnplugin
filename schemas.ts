const configSchema = {
	$id: '#/plugins/idnttycoreapi/config',
	type: 'object',
	properties: {
        enable: {
			type: 'boolean'
		},
		port: {
			type: 'integer',
			minimum: 1,
			maximum: 65535,
		},
		host: {
			type: 'string',
			format: 'ip',
		},
		whiteList: {
			type: 'array',
			items: {
				type: 'string',
			},
		},
		redisConnectionString: {
			type: 'string',
		},
        publicKey: {
			type: 'string',
		},
        serviceFee: {
			type: 'integer',
		},  
		cors: {
			type: 'object',
			properties: {
				origin: {
					anyOf: [{ type: 'string' }, { type: 'boolean' }],
				},
				methods: {
					type: 'array',
				},
			},
			required: ['origin'],
		},
		limits: {
			type: 'object',
			properties: {
				max: {
					type: 'integer',
				},
				delayMs: {
					type: 'integer',
				},
				delayAfter: {
					type: 'integer',
				},
				windowMs: {
					type: 'integer',
				},
				headersTimeout: {
					type: 'integer',
					minimum: 1,
					maximum: 40000,
				},
				serverSetTimeout: {
					type: 'integer',
					minimum: 1,
					maximum: 120000,
				},
			},
			required: ['max', 'delayMs', 'delayAfter', 'windowMs', 'headersTimeout', 'serverSetTimeout'],
		},
	},
	required: ['port', 'whiteList', 'cors', 'limits'],
	default: {
        enable: false,
		port: 8090,
		host: '127.0.0.1',
		whiteList: ['127.0.0.1'],
		cors: {
			origin: '*',
			methods: ['GET', 'POST', 'PUT'],
		},
		limits: {
			max: 0,
			delayMs: 0,
			delayAfter: 0,
			windowMs: 60000,
			headersTimeout: 5000,
			serverSetTimeout: 20000,
		},
        redisConnectionString: "redis://localhost",
        publicKey: "91a1559b46f72f1c4773ec1a53ad514fb3658d88f05bf7b97deb12d35656db97",
        serviceFee: 50,
	},
};


module.exports = {configSchema}