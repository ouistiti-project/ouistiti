class ChatUser
{
	constructor(nickname, color)
	{
		this.nickname = nickname;
		this.color = color;
		this.id = nickname;
	}
};

class Chat
{
	constructor(uri)
	{
		this.ouistitiserver = true;
		this.uri = uri;
		this.user = undefined;
		this.ws = undefined;
		this.onconnect = undefined;
		this.onclose = undefined;
		this.onmessage = undefined;
		this.onhello = undefined;
		this.ongoodbye = undefined;
		this.onalert = undefined;
		Notification.requestPermission()
	}

	connect()
	{
		if (this.user == undefined)
			return;
		this.ws = new WebSocket(this.uri, "chat");
		this.ws.onopen = function(evt) { this._onopen.call(this, evt) }.bind(this);
		this.ws.onclose = function(evt) { this._onclose.call(this, evt) }.bind(this);
		this.ws.onmessage = function(evt) { this._onmessage.call(this, evt) }.bind(this);
		this.ws.onerror = function(evt) { this._onerror.call(this, evt) }.bind(this);
	}

	disconnect()
	{
		if (this.ws != undefined)
		{
			var msg = {type : "goodbye", id: this.id, data: this.user};
			this.ws.send(JSON.stringify(msg));
		}
	};

	_onopen(evt)
	{
		if (this.ouistitiserver)
			this.ws.send("WSHello "+this.user.nickname);
		else
			this.hello();
		if (typeof(this.onconnect) == "function")
			this.onconnect();
	}
	_onclose(evt)
	{
		if (typeof(this.onclose) == "function")
			this.onclose();
		this.ws.close();
	}
	_onmessage(evt)
	{
		var data = evt.data;
		if (this.ouistitiserver && data.substr(0, 10) == "WSWelcome ")
		{
			this.user.id = data.substr(10);
			this.hello();
		}
		else if (this.ouistitiserver && data.substr(0, 5) == "WSIs ")
		{
			this.onalert(data.substr(5));
		}
		else
		{
			//data = data.substr(0, data.length - 1);
			msg = JSON.parse(data);
			if (msg != undefined)
			{
				switch (msg.type)
				{
					case "hello":
					{
						if (typeof(this.onhello) == "function")
							this.onhello(msg.data);
						this.welcome();
					}
					break;
					case "welcome":
					{
						if (typeof(this.onhello) == "function")
							this.onhello(msg.data);
					}
					break;
					case "message":
					{
						if (typeof(this.onmessage) == "function")
							this.onmessage(msg);
					}
					break;
					case "private":
					{
						if (typeof(this.onmessage) == "function")
							this.onmessage(msg);
					}
					break;
					case "goodbye":
					{
						if (typeof(this.ongoodbye) == "function")
							this.ongoodbye(msg.data);
					}
					break;
					case "whois":
					{
						if (this.user.id == message.data)
						{
							var msg = {type : "is", id: this.user.id, data: this.user, private:message.id};
							this.ws.send(JSON.stringify(msg));
						}
					}
					break;
					case "is":
					{
						if (message.private == this.user.id)
							this.onalert(message.data);
					}
					break;
				}
			}
		}
	}
	_onerror(evt)
	{
		this.ws.close();
	}
	send(text, privatemsg)
	{
		var msg = {type : "message", id: this.user.id, data: text};
		if (privatemsg != undefined)
			msg.private = privatemsg;
		if (this.ouistitiserver && privatemsg != undefined)
			this.ws.send("WSPrivate "+privatemsg+" "+JSON.stringify(msg));
		else
			this.ws.send(JSON.stringify(msg));
		
		if (typeof(this.onmessage) == "function")
			this.onmessage(msg);
	};

	hello()
	{
		var msg = {type : "hello", id: this.user.id, data: this.user};
		var msg_str = JSON.stringify(msg);
		this.ws.send(msg_str);
	};

	welcome()
	{
		var msg = {type : "welcome", id: this.user.id, data: this.user};
		this.ws.send(JSON.stringify(msg));
	};

	whois(id)
	{
		if (this.ouistitiserver)
			this.ws.send("WSWhois "+id);
		else
		{
			var msg = {type : "whois", id: this.user.id, data: id};
			this.ws.send(JSON.stringify(msg));
		}
	}

};
