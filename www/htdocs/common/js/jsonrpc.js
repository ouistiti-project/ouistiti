function loadSymbol(functionName, context /*, args */) {
  var namespaces = functionName.split(".");
  var func = namespaces.pop();
  for(var i = 0; i < namespaces.length; i++) {
    context = context[namespaces[i]];
  }
  return context[func];
}

class JsonRPC{
	#cmds = new Map();
	constructor(url)
	{
		this.prototype = Object.create(EventTarget.prototype);
		this.urlsocket = "";
		if (url != undefined && url.match(/^ws[s]:\/\//))
			this.urlsocket = url;
		else
		{
			if (location.protocol === "http:")
				this.urlsocket = "ws://";
			else if (location.protocol === "https:")
				this.urlsocket = "wss://";
			this.urlsocket += location.hostname;
			this.urlsocket += ":"+location.port;
			this.urlsocket += "/"+url;
		}
		this.id = 0;
		this.wsready = false;
		this.cnt = 0;
		this.string = "";
		this.cmds = new Array();
	}

	connect()
	{
		this.websocket=new WebSocket(this.urlsocket);

		this.websocket.onopen = function(evt) {
			this.wsready = true;
			console.log("socket open: ", evt);
			if (typeof(this.onopen) == "function")
				this.onopen.call(this);
		}.bind(this);
		this.websocket.onmessage = this.receive.bind(this);
		this.websocket.onerror = function(evt)
		{
			console.log("socket error: ", evt);
			this.string = "";
			this.cnt = 0;
		}.bind(this);
		this.websocket.onclose = function(evt)
		{
			this.wsready = false;
			console.log("socket close: ", evt);
			if (typeof(this.onclose) == "function")
				this.onclose.call(this);
		}.bind(this);
	}

	runRPC(string)
	{
		var data;
		try {
			data = JSON.parse(string);
		}
		catch(error) {
			console.log("recv: "+string);
			console.log(error);
			return;
		}
		if (data.id != undefined)
		{
			if (this.#cmds.has(data.id))
			{
				data.request = this.#cmds.get(data.id);
				data.method = data.request.method;
			}
			else
				console.log("method id  "+data.id + "not found");
			this.#cmds.delete(data.id);
		}
		if (data.error)
		{
			console.log("response error  "+data.error);
			if (typeof(this.onerror) == "function")
				this.onerror.call(this, data.error, data.request);
		}
		else if (data.method)
		{
			if (typeof(this.respond) == "function")
				this.respond.call(this, data.result);
			this.respond = undefined;
			var func = loadSymbol(data.method, this);
			if (data.result && typeof(func) == "function")
			{
				//console.log("response "+data.method);
				func.call(this,data.result);
			}
			else if (data.params && typeof(func) == "function")
			{
				//console.log("notification "+data.method);
				func.call(this,data.params);
			}
			else
				console.log("method "+data.method + " not connected to "+typeof(func));
		}
		if (typeof(this.onmessage) == "function")
			this.onmessage.call(this, data);
	}

	receive(evt)
	{
		//console.log("receive : "+evt.data);
		let doubleresponse = evt.data.search("}{");
		if (doubleresponse != -1)
		{
			let first = evt.data.substr(0, doubleresponse + 1);
			this.runRPC(first);
			evt.data = evt.data.substr(doubleresponse + 1);
		}
		this.runRPC(evt.data);
	}

	close()
	{
		this.websocket.close();
	}

	send(method, params, respond)
	{
		//console.log("send "+method);
		this.respond = respond;
		var request = new Object();
		request.jsonrpc = "2.0";
		request.method = method.toString();
		var paramsstr;
		if (typeof(params) == "object")
			request.params = params;
		else
		{
			try {
				request.params = JSON.parse(params);
			}
			catch(error) {
				console.log("jsonrpc params: "+params);
				console.log(error);
				return;
			}
		}
		request.id = this.id;

		if (this.wsready)
		{
			var msg = JSON.stringify(request);
			this.#cmds.set(this.id, request);
			//console.log("send :"+msg);
			this.websocket.send(msg);
			this.id++;
		}
	}
}
