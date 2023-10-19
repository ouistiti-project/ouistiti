class MultipartMessager
{
	#headers = undefined;
	#body = undefined;
	#isstarted = false;
	#boundary = undefined;
	#headerlength = 0;
	constructor(boundary)
	{
		this.#body = new Uint8Array(0);
		this.#headers = new Headers();
		this.#isstarted = false;
		this.#boundary = boundary;
		this.onResponse = null;
		this.textdecoder = new TextDecoder;
	}
	addData(packet)
	{
		let usedbytes = 0;
		let body = undefined;
		if (!this.#isstarted)
		{
			try {
				body = this.#parse(packet);
				let rest = body.length;
				if (! this.#headers.has("Content-Length"))
				{
					throw Error("Boundary content error");
				}
				if (body.length > this.#headers.get("Content-Length"))
				{
					rest = this.#headers.get("Content-Length");
				}
				// the length of the boundary + headers
				usedbytes = packet.length - rest;
				this.#isstarted = true;
			}
			catch(e) {
				console.log(e.message, packet);
				usedbytes += packet.length;
			}
		}
		else
		{
			body = new Uint8Array(this.#body.length + packet.length);
			body.set(this.#body);
			// the length of the current body will be added again
			usedbytes -= this.#body.length;
			body.set(packet, this.#body.length);
		}
		if (body.length > this.#headers.get("Content-Length"))
		{
			body = body.slice(0, this.#headers.get("Content-Length"));
		}
		// the length of the FULL body
		usedbytes += body.length;
		this.#body = body;
		if (body.length == this.#headers.get("Content-Length") && typeof this.onResponse === 'function')
		{
			//console.log("Multipart body", this.#body);
			let response = new Response(this.#body, {status: 200, headers: this.#headers});
			this.onResponse(response);
			this.#body = new Uint8Array(0);
			this.#headers = new Headers();
			this.#isstarted = false;
		}
		return usedbytes;
	}
	#parseboundary(value)
	{
		const boundaryid = value.indexOf('-'.charCodeAt(0));				
		if (boundaryid == -1 || value[boundaryid + 1] != '-'.charCodeAt(0))
		{
			return undefined;
		}
		return value.subarray(boundaryid + 2);
	}
	#parse(value)
	{
		value = this.#parseboundary(value);
		if (value == undefined)
			throw new Error("Boundary not found");

		let boundary = this.#splitheader(value);
		value = value.subarray(boundary.byteLength);
		if (this.textdecoder.decode(boundary) === this.#boundary)
			throw new Error("Boundary attack");
		do
		{
			let header = this.#splitheader(value);
			value = value.subarray(header.length);
			if (header.length < 3)
				break;
			let [key, data] = this.textdecoder.decode(header).split(':');
			this.#headers.append(key, data.trim());
		} while(value.length > 2);
		return value;
	}
	#splitheader(value)
	{
		let endlineid = undefined;
		let header = undefined;
		do
		{
			endlineid = value.indexOf('\r'.charCodeAt(0));
			if (endlineid == -1)
				throw new Error("Data malformatted");
			header = value.slice(0, endlineid + 2);
			value = value.subarray(endlineid + 1);
		} while (value[0] != '\n'.charCodeAt(0));
		value = value.subarray(1);
		return header;
	}
}

const tcontent = {
	start(controller)
	{
		this.messager.onResponse = function(response) {
			controller.enqueue(response);
		};
		this.push(controller);
	},
	async transform(chunk, controller)
	{
		chunk = await chunk;
		return this._transform(chunk, controller);
	},
	_transform(chunk, controller)
	{
		let data = null
		if (ArrayBuffer.isView(chunk))
		{
			data = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
		}
		else if (Array.isArray(chunk) && chunk.every(value => typeof value === 'number'))
		{
			data = new Uint8Array(chunk);
		}
		if (data != null)
		{
			let used = 0;
			do {
				used = this.messager.addData(data);
				let tempo = data.slice(used);
//				if (tempo.length > 0)
				{
//					console.log("data = "+ data.length + " used = "+used + " rest = "+tempo.length);
//					console.log("second message", tempo);
				}
				data = tempo;
			} while (data.length > 0);
		}
	},
	push(controller)
	{
		this.reader.read()
		.then(function({done, value}) {
			if (done)
			{
				controller.close();
				throw new Error("Connection closed");
			}
			this._transform(value, controller);
			this.push(controller);
		}.bind(this))
		.catch(function(error) {
			console.log("ABORTING");
		}.bind(this));
	},
	cancel(reason)
	{
		this.reader.abortcontroller.abort();
	}
}

/*
class MultipartTransformStream extends TransformStream
{
	messager = undefined;

	constructor(boundary)
	{
		super({...tcontent, messager: new MultipartMessager(boundary)});
	}
}

async function fetchmultipart(url)
{
	let boundary = undefined;
	return fetch(url)
	.then(function(response) {
			if(response.ok)
			{
				let contenttype = response.headers.get("Content-TYpe");
				boundary = contenttype;
				return response.body;
			}
			throw new Error("bad response");
	})
	.then(function(body) {
		return body.pipeThrough(new MultipartTransformStream(boundary));
	});
}
*/

class MultipartReadableStream extends ReadableStream
{
	messager = undefined;

	constructor(boundary, reader)
	{
		super({...tcontent, messager: new MultipartMessager(boundary), reader: reader});
	}
}

async function fetchmultipart(url)
{
	const controller = new AbortController();
	const signal = controller.signal;
	let boundary = undefined;
	return fetch(url, {signal})
	.then(function(response) {
			if(response.ok)
			{
				let contenttype = response.headers.get("Content-TYpe");
				boundary = contenttype.split(';').find(element => element.indexOf('boundary=') != -1);
				if (boundary == undefined)
					throw new Error("Not a multipart response");
				boundary = boundary.split('=')[1].trim();
				return response.body;
			}
			throw new Error("bad response");
	})
	.then(function(body) {
		const reader = body.getReader();
		reader.abortcontroller = controller;
		return new MultipartReadableStream(boundary, reader);
	});
}
