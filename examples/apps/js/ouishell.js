var MD5 = function(s){function L(k,d){return(k<<d)|(k>>>(32-d))}function K(G,k){var I,d,F,H,x;F=(G&2147483648);H=(k&2147483648);I=(G&1073741824);d=(k&1073741824);x=(G&1073741823)+(k&1073741823);if(I&d){return(x^2147483648^F^H)}if(I|d){if(x&1073741824){return(x^3221225472^F^H)}else{return(x^1073741824^F^H)}}else{return(x^F^H)}}function r(d,F,k){return(d&F)|((~d)&k)}function q(d,F,k){return(d&k)|(F&(~k))}function p(d,F,k){return(d^F^k)}function n(d,F,k){return(F^(d|(~k)))}function u(G,F,aa,Z,k,H,I){G=K(G,K(K(r(F,aa,Z),k),I));return K(L(G,H),F)}function f(G,F,aa,Z,k,H,I){G=K(G,K(K(q(F,aa,Z),k),I));return K(L(G,H),F)}function D(G,F,aa,Z,k,H,I){G=K(G,K(K(p(F,aa,Z),k),I));return K(L(G,H),F)}function t(G,F,aa,Z,k,H,I){G=K(G,K(K(n(F,aa,Z),k),I));return K(L(G,H),F)}function e(G){var Z;var F=G.length;var x=F+8;var k=(x-(x%64))/64;var I=(k+1)*16;var aa=Array(I-1);var d=0;var H=0;while(H<F){Z=(H-(H%4))/4;d=(H%4)*8;aa[Z]=(aa[Z]| (G.charCodeAt(H)<<d));H++}Z=(H-(H%4))/4;d=(H%4)*8;aa[Z]=aa[Z]|(128<<d);aa[I-2]=F<<3;aa[I-1]=F>>>29;return aa}function B(x){var k="",F="",G,d;for(d=0;d<=3;d++){G=(x>>>(d*8))&255;F="0"+G.toString(16);k=k+F.substr(F.length-2,2)}return k}function J(k){k=k.replace(/rn/g,"n");var d="";for(var F=0;F<k.length;F++){var x=k.charCodeAt(F);if(x<128){d+=String.fromCharCode(x)}else{if((x>127)&&(x<2048)){d+=String.fromCharCode((x>>6)|192);d+=String.fromCharCode((x&63)|128)}else{d+=String.fromCharCode((x>>12)|224);d+=String.fromCharCode(((x>>6)&63)|128);d+=String.fromCharCode((x&63)|128)}}}return d}var C=Array();var P,h,E,v,g,Y,X,W,V;var S=7,Q=12,N=17,M=22;var A=5,z=9,y=14,w=20;var o=4,m=11,l=16,j=23;var U=6,T=10,R=15,O=21;s=J(s);C=e(s);Y=1732584193;X=4023233417;W=2562383102;V=271733878;for(P=0;P<C.length;P+=16){h=Y;E=X;v=W;g=V;Y=u(Y,X,W,V,C[P+0],S,3614090360);V=u(V,Y,X,W,C[P+1],Q,3905402710);W=u(W,V,Y,X,C[P+2],N,606105819);X=u(X,W,V,Y,C[P+3],M,3250441966);Y=u(Y,X,W,V,C[P+4],S,4118548399);V=u(V,Y,X,W,C[P+5],Q,1200080426);W=u(W,V,Y,X,C[P+6],N,2821735955);X=u(X,W,V,Y,C[P+7],M,4249261313);Y=u(Y,X,W,V,C[P+8],S,1770035416);V=u(V,Y,X,W,C[P+9],Q,2336552879);W=u(W,V,Y,X,C[P+10],N,4294925233);X=u(X,W,V,Y,C[P+11],M,2304563134);Y=u(Y,X,W,V,C[P+12],S,1804603682);V=u(V,Y,X,W,C[P+13],Q,4254626195);W=u(W,V,Y,X,C[P+14],N,2792965006);X=u(X,W,V,Y,C[P+15],M,1236535329);Y=f(Y,X,W,V,C[P+1],A,4129170786);V=f(V,Y,X,W,C[P+6],z,3225465664);W=f(W,V,Y,X,C[P+11],y,643717713);X=f(X,W,V,Y,C[P+0],w,3921069994);Y=f(Y,X,W,V,C[P+5],A,3593408605);V=f(V,Y,X,W,C[P+10],z,38016083);W=f(W,V,Y,X,C[P+15],y,3634488961);X=f(X,W,V,Y,C[P+4],w,3889429448);Y=f(Y,X,W,V,C[P+9],A,568446438);V=f(V,Y,X,W,C[P+14],z,3275163606);W=f(W,V,Y,X,C[P+3],y,4107603335);X=f(X,W,V,Y,C[P+8],w,1163531501);Y=f(Y,X,W,V,C[P+13],A,2850285829);V=f(V,Y,X,W,C[P+2],z,4243563512);W=f(W,V,Y,X,C[P+7],y,1735328473);X=f(X,W,V,Y,C[P+12],w,2368359562);Y=D(Y,X,W,V,C[P+5],o,4294588738);V=D(V,Y,X,W,C[P+8],m,2272392833);W=D(W,V,Y,X,C[P+11],l,1839030562);X=D(X,W,V,Y,C[P+14],j,4259657740);Y=D(Y,X,W,V,C[P+1],o,2763975236);V=D(V,Y,X,W,C[P+4],m,1272893353);W=D(W,V,Y,X,C[P+7],l,4139469664);X=D(X,W,V,Y,C[P+10],j,3200236656);Y=D(Y,X,W,V,C[P+13],o,681279174);V=D(V,Y,X,W,C[P+0],m,3936430074);W=D(W,V,Y,X,C[P+3],l,3572445317);X=D(X,W,V,Y,C[P+6],j,76029189);Y=D(Y,X,W,V,C[P+9],o,3654602809);V=D(V,Y,X,W,C[P+12],m,3873151461);W=D(W,V,Y,X,C[P+15],l,530742520);X=D(X,W,V,Y,C[P+2],j,3299628645);Y=t(Y,X,W,V,C[P+0],U,4096336452);V=t(V,Y,X,W,C[P+7],T,1126891415);W=t(W,V,Y,X,C[P+14],R,2878612391);X=t(X,W,V,Y,C[P+5],O,4237533241);Y=t(Y,X,W,V,C[P+12],U,1700485571);V=t(V,Y,X,W,C[P+3],T,2399980690);W=t(W,V,Y,X,C[P+10],R,4293915773);X=t(X,W,V,Y,C[P+1],O,2240044497);Y=t(Y,X,W,V,C[P+8],U,1873313359);V=t(V,Y,X,W,C[P+15],T,4264355552);W=t(W,V,Y,X,C[P+6],R,2734768916);X=t(X,W,V,Y,C[P+13],O,1309151649);Y=t(Y,X,W,V,C[P+4],U,4149444226);V=t(V,Y,X,W,C[P+11],T,3174756917);W=t(W,V,Y,X,C[P+2],R,718787259);X=t(X,W,V,Y,C[P+9],O,3951481745);Y=K(Y,h);X=K(X,E);W=K(W,v);V=K(V,g)}var i=B(Y)+B(X)+B(W)+B(V);return i.toLowerCase()};

class User
{
	constructor(name, group, home)
	{
		this.name = name;
		this.group = group;
		this.home = home;
		this.directories =
		{
			image:"/Images",
			music:"/Musics",
			share:"/Public",
			documents:"/Documents",
			private:"/Private"
		};
		this.mimes = 
		[
			{ type:"image/*",appli:"ouialbum.html"},
			{ type:"audio/*",appli:"ouiplaymusic.html"}
		];
	}
};

class Authenticate
{
	constructor(challenge)
	{
		this.uploadXHR = new XMLHttpRequest();
		this.encoder = new TextEncoder("utf-8");
		this.challenge = challenge;
		this.user = undefined;
		this.username = undefined;
		this.password = undefined;
		this.authorization = undefined;
		this.method = "HEAD";
		// remove the file's name from pathname
		this.url = location.pathname.replace(/\\/g,'/').replace(/\/[^\/]*$/, '')
		this.islog = false;
		this.onauthorization = undefined;
		this.onauthenticate = undefined;
		this.onnotfound = undefined;
		this.algo = MD5;
		/*
		this.algo = function(text)
		{
			return crypto.subtle.digest("SHA-256", buffer).then(function (hash) {
				return hex(hash);
			});
		};
		*/
	}

	generateid()
	{
		var array = new Uint32Array(1);
		window.crypto.getRandomValues(array);
		return array[0];
	}

	basic()
	{
		return "Basic "+window.btoa(this.username+":"+this.password);
	}
	digest()
	{
		var challenge = this.challenge.split(",");
		var realm = challenge.find(function(elm) { return elm.startsWith("realm=");}).split(" ")[0].split("=");
		var uri = this.url;
		var nonce = challenge.find(function(elm) { return elm.startsWith("nonce=");}).split(" ")[0].split("=");
		var qop   = challenge.find(function(elm) { return elm.startsWith("qop="  );}).split(" ")[0].split("=");
		var digest = "";
		var a1= this.encoder.encode(this.username+":"+realm+":"+this.password);
		var a2= this.encoder.encode(this.method+":"+uri);
		digest=atob(this.algo(a1))+":"+nonce+":";
		if (qop === "auth")
			digest += this.nc+":"+this.cnonce+":";
		digest+=atob(this.algo(a2));
		return digest;
	}

	build()
	{
		if (this.challenge.search("Digest") > -1)
			this.authorization = this.digest();
		else if (this.challenge.search("Basic") > -1)
			this.authorization = this.basic();
		this.result = "failed";
	}

	remove()
	{
//		const xhr = new XMLHttpRequest();
		const xhr = this.uploadXHR;
		document.cookie = "Authorization=;";
		this.authorization = undefined;
		this.result = "logout";
		this.user = undefined;
		xhr.onreadystatechange = function()
		{
			if (xhr.readyState === XMLHttpRequest.DONE)
			{
				if (xhr.status === 401 || xhr.status === 403)
				{
					if (this.onauthenticate != undefined)
						this.onauthenticate.call(this, xhr.getResponseHeader("WWW-Authenticate"), "logout");
					window.location = xhr.responseURL;
				}
				else if (xhr.status > 0 && this.onerror != undefined)
				{
					this.onerror.call(this, xhr.status);
				}
			}
		}.bind(this);
		xhr.open(this.method, "/?"+this.generateid(), true);
		xhr.setRequestHeader("WWW-Authenticate", "None");
		xhr.setRequestHeader("Authorization", "None");
		xhr.send();
	}
	get()
	{
		const xhr = this.uploadXHR;

		xhr.onreadystatechange = function()
		{
			if (xhr.readyState === XMLHttpRequest.DONE)
			{
				if (xhr.status === 200)
				{
					if (this.authorization && this.authorization.length > 0)
						document.cookie = "Authorization="+this.authorization+";"+document.cookie;
					var username = xhr.getResponseHeader("X-Remote-User");
					if (username != undefined)
					this.user = new User(username, xhr.getResponseHeader("X-Remote-Group"), xhr.getResponseHeader("X-Remote-Home"));
					this.islog = true;
					if (this.onauthorization != undefined)
						this.onauthorization.call(this, this.user);
				}
			}
			else if (xhr.readyState >= XMLHttpRequest.LOADING &&
					xhr.status > 399)
			{
				if (xhr.status === 403)
				{
					var challenge = xhr.getResponseHeader("WWW-Authenticate");
					this.authorization = undefined;
					if (challenge != undefined)
						this.challenge = challenge;
					this.islog = false;
					if (this.onauthenticate != undefined)
						this.onauthenticate.call(this, this.challenge, this.result);
				}
				else if (xhr.status === 404)
				{
					if (this.onnotfound != undefined)
						this.onnotfound.call(this);
				}
				else if (this.onerror != undefined)
				{
					this.onerror.call(this, xhr.status);
				}
				if (xhr.readyState === XMLHttpRequest.LOADING)
					xhr.abort();
			}
			return true;
		}.bind(this);
		xhr.open(this.method, this.url, true);
		if (this.authorization != undefined)
		{
			xhr.withCredentials = true;
			xhr.setRequestHeader("Authorization", this.authorization);
		}
		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
		xhr.send();
	}
};
class Open
{
	constructor(root)
	{
		this.root = root;
		this.uploadXHR = new XMLHttpRequest();
		this.isready = false;
		this.onload = undefined;
		this.onauthenticate = undefined;
		this.onnotfound = undefined;
	}

	open(directory)
	{
		if (directory[0] != '/')
			this.directory = this.root;
		else
			this.directory = "";
		this.directory += directory
		var length = this.directory.length - 1;
		if (this.directory.charAt(length) != '/')
			this.directory += '/';
	}
	set(file)
	{
		this.file = file;
	}
	exec(authorization)
	{
		const xhr = this.uploadXHR;

		xhr.onreadystatechange = function()
		{
			if (xhr.readyState === XMLHttpRequest.DONE)
			{
				if (xhr.status === 200)
				{
					this.isready = false;
					if (this.onload != undefined)
					{
						xhr.response.name = this.file.name;
						xhr.response.newname = this.file.newname;
						xhr.response.oldname = this.file.oldname;
						this.onload.call(this, xhr.response);
					}
				}
			}
			else if (xhr.readyState >= XMLHttpRequest.LOADING &&
					xhr.status > 399)
			{
			
				if (xhr.status === 403)
				{
					if (this.onauthenticate != undefined)
						this.onauthenticate.call(this, xhr.getResponseHeader("WWW-Authenticate"), "logout");
				}
				else if (xhr.status === 404)
				{
					if (this.onnotfound != undefined)
					{
						var url = document.createElement('a');
						url.href = xhr.responseURL;
						this.onnotfound.call(this, url);
					}
				}
				else if (this.onerror != undefined)
				{
					this.onerror.call(this, xhr.status);
				}
				if (xhr.readyState === XMLHttpRequest.LOADING)
					xhr.abort();
			}
			return true;
		}.bind(this);
		var target = this.directory;
		if (this.file.name == undefined)
			this.file.name = "";
		target += this.file.name; 
		
		xhr.open("GET", target);
		//xhr.responseType = "arraybuffer";
		xhr.responseType = "blob";
		xhr.withCredentials = true;
		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
		if (authorization)
			xhr.setRequestHeader("Authorization",authorization);
		xhr.send();
	}

	go(target, search)
	{
		var targetlocation = target.split("://");
		var scheme;
		var hostname;
		var pathname;
		if (targetlocation.length == 2)
		{
			scheme = targetlocation[0];
			var index = targetlocation[1].indexOf("/");
			hostname = targetlocation[1].substring(0, index);
			pathname = targetlocation[1].substring(index);
		}
		else if (targetlocation.length == 1)
		{
			scheme = location.protocol.replace(/:?$/, '');
			hostname = location.hostname;
			pathname = targetlocation[0];
			if (!pathname.startsWith('/'))
				pathname = this.directory+pathname;
		}
		switch (scheme)
		{
			case "http":
			case "https":
				window.open(scheme+"://"+hostname+pathname+search);
			break;
		}
	}
};
class Remove
{
	constructor(root)
	{
		this.root = root;
		this.uploadXHR = new XMLHttpRequest();
		this.isready = false;
		this.onload = undefined;
		this.onauthenticate = undefined;
		this.onnotfound = undefined;
	}

	open(directory)
	{
		if (directory[0] != '/')
			this.directory = this.root;
		else
			this.directory = "";
		this.directory += directory
		var length = this.directory.length - 1;
		if (this.directory.charAt(length) != '/')
			this.directory += '/';
	}

	set(file)
	{
		this.file = file;
	}

	exec(authorization)
	{
		const xhr = this.uploadXHR;

		xhr.onreadystatechange = function()
		{
			if (xhr.readyState === XMLHttpRequest.DONE)
			{
				if (xhr.status === 200)
				{
					this.isready = false;
					if (this.onload != undefined)
					{
						this.file.data = JSON.parse(xhr.responseText);
						this.onload.call(this, this.file);
					}
				}
			}
			else if (xhr.readyState >= XMLHttpRequest.LOADING &&
					xhr.status > 399)
			{
				if (xhr.status === 403)
				{
					if (this.onauthenticate != undefined)
						this.onauthenticate.call(this, xhr.getResponseHeader("WWW-Authenticate"), "logout");
				}
				else if (xhr.status === 404)
				{
					if (this.onnotfound != undefined)
						this.onnotfound.call(this, xhr.responseURL);
				}
				else if (this.onerror != undefined)
				{
					this.onerror.call(this, xhr.status);
				}
				if (xhr.readyState === XMLHttpRequest.LOADING)
					xhr.abort();
			}
			return true;
		}.bind(this);
		var directory = this.directory;
		if (this.directory == undefined)
			directory = "";
		xhr.open("DELETE", directory+this.file.name);
		xhr.responseType = "text/json";
		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
		if (authorization)
			xhr.setRequestHeader("Authorization",authorization);
		xhr.send();
	}
};
class Change
{
	constructor(root)
	{
		this.root = root;
		this.uploadXHR = new XMLHttpRequest();
		this.isready = false;
		this.onload = undefined;
		this.onauthenticate = undefined;
		this.onnotfound = undefined;
		this.post = new Object();
		this.post.type = "header";
	}

	open(directory)
	{
		if (directory[0] != '/')
			this.directory = this.root;
		else
			this.directory = "";
		this.directory += directory
		var length = this.directory.length - 1;
		if (this.directory.charAt(length) != '/')
			this.directory += '/';
	}

	set(file)
	{
		this.file = file;
	}

	command(message, type)
	{
		if (type != undefined)
			this.post.type = type;
		else
			this.post.type = "header";
		if (this.post.type == "text/json")
			this.post.data = JSON.stringify(message);
		else
			this.post.data = message;
	}

	exec(authorization)
	{
		const xhr = this.uploadXHR;

		xhr.onreadystatechange = function()
		{
			if (xhr.readyState === XMLHttpRequest.DONE)
			{
				if (xhr.status === 200)
				{
					this.isready = false;
					if (this.onload != undefined)
					{
						var type = xhr.getResponseHeader("Content-Type");
						if (type == "text/json")
							this.file.data = JSON.parse(xhr.response);
						else
							this.file.data = xhr.response;
						this.onload.call(this, file);
					}
				}
			}
			else if (xhr.readyState >= XMLHttpRequest.LOADING &&
					xhr.status > 399)
			{
				if (xhr.status === 403)
				{
					if (this.onauthenticate != undefined)
						this.onauthenticate.call(this, xhr.getResponseHeader("WWW-Authenticate"), "logout");
				}
				else if (xhr.status === 404)
				{
					if (this.onnotfound != undefined)
						this.onnotfound.call(this, xhr.responseURL);
				}
				else if (this.onerror != undefined)
				{
					this.onerror.call(this, xhr.status);
				}
				if (xhr.readyState === XMLHttpRequest.LOADING)
					xhr.abort();
			}
			return true;
		}.bind(this);
		var directory = this.directory;
		if (this.directory == undefined)
			directory = "";
		xhr.open("POST", directory+this.file.name);
		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");

		if (this.post.type == "header")
		{
			xhr.setRequestHeader("X-POST-CMD", this.post.data.cmd);
			xhr.setRequestHeader("X-POST-ARG", this.post.data.arg);
			this.post.data = undefined;
		}
		else
		{
			xhr.setRequestHeader("Content-Type", this.post.type);
		}
		if (authorization)
			xhr.setRequestHeader("Authorization",authorization);
		xhr.send(this.post.data);
	}
};
class UpLoader
{
	constructor(root)
	{
		this.root = root;
		this.uploadXHR = new XMLHttpRequest();
		this.reader = new FileReader();
		this.file = undefined;
		this.directory = undefined;
		this.isready = false;
		this.onload = undefined;
		this.onupload = undefined;
		this.onauthenticate = undefined;
		this.onnotfound = undefined;
	}

	open(directory)
	{
		if (directory[0] != '/')
			this.directory = this.root;
		else
			this.directory = "";
		this.directory += directory
		var length = this.directory.length - 1;
		if (this.directory.charAt(length) != '/')
			this.directory += '/';
	}
	set(file)
	{
		this.file = file;
	}
	get(file, offset)
	{
		if (offset != undefined)
			return;
		this.file = file;
		this.reader.onloadend = function(evt)
			{
				const array = new Uint8ClampedArray(evt.target.result);
				this.file.data = array;

				if (this.reader.readyState == 2)
				{
					this.isready = true;
					if (this.onload != undefined)
						this.onload.call(this, this.file);
				}
			}.bind(this);
		this.reader.onerror = function(err) {
          alert("load error "+err);
        }.bind(this);
		this.reader.readAsArrayBuffer(this.file);
	}
	exec(authorization)
	{
		const xhr = this.uploadXHR;

		xhr.upload.onprogress = function(event)
		{
			if (this.onprogress != undefined)
				this.onprogress(event.loaded, event.total);
		}.bind(this);
		xhr.onreadystatechange = function()
		{
			if (xhr.readyState === XMLHttpRequest.DONE)
			{
				if (xhr.status === 200)
				{
					this.isready = false;
					if (this.onupload != undefined)
						this.onupload.call(this, JSON.parse(xhr.responseText));
					this.file = undefined;
				}
			}
			else if (xhr.readyState >= XMLHttpRequest.LOADING &&
					xhr.status > 399)
			{
				if (xhr.status === 403 || xhr.status === 401)
				{
					if (this.onauthenticate != undefined)
						this.onauthenticate.call(this, xhr.getResponseHeader("WWW-Authenticate"), "logout");
				}
				else if (xhr.status === 404)
				{
					if (this.onnotfound != undefined)
					{
						var url = document.createElement('a');
						url .href = xhr.responseURL;
						this.onnotfound.call(this, url);
					}
				}
				else if (xhr.status === 416)
				{
					var crange = xhr.getResponseHeader("Content-Range");
					if (crange != undefined)
					{
						var offset = crange.substring(0,crange.indexOf("/"));
						if (this.file.size > offset)
							this.get(this.file,offset);
						else if (this.onerror != undefined)
							this.onerror.call(this, xhr.status);
					}
				}
				else if (this.onerror != undefined)
				{
					this.onerror.call(this, xhr.status);
				}
				if (xhr.readyState === XMLHttpRequest.LOADING)
					xhr.abort();
			}
			return true;
		}.bind(this);
		xhr.ontimeout = function()
		{
			alert("Uploader timeout");
		}.bind(this);
		var data = undefined;
		if (this.file != undefined)
		{
			var filename = this.directory+this.file.name;
			xhr.open("PUT", filename);
			data = this.file;
		}
		else
		{
			xhr.open("PUT", this.directory);
		}
		xhr.responseType = "text/json";
		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
		if (authorization)
			xhr.setRequestHeader("Authorization",authorization);
		xhr.send(data);
	}
};
class Shell
{
	constructor(output)
	{
		this.directories =
		{
			image:"/public/images",
			music:"/public/musics",
			share:"/public",
			documents:"/",
			private:"/private"
		};
		var search = location.search.substring(1).split("&");
		var root = search.find(function(elem){
				return elem.startsWith("root=");
			});
		this.root = "/";
		if (root)
		{
			root = root.split("=")[1];
		}
		else
		{
			//remove the last part of the pathname, the name of the file and the rest...
			root = location.pathname.replace(/\\/g,'/').replace(/\/[^\/]*$/, '').replace(/^\/?|\/?$/, '');
		}
		if (root.lastIndexOf('/') != root.length - 1)
			root += '/';
		this.root += root.replace(/\\/g,'/').replace(/^\/?|\/?$/, '');
		if (this.root == "/")
			this.root = "";
		var cwd = search.find(function(elem){
				return elem.startsWith("cwd=");
			});
		if (cwd)
		{
			cwd = cwd.split("=")[1];
			if (cwd.lastIndexOf('/') != cwd.length - 1)
				cwd += '/';
			this.cwd = cwd.replace(/\\/g,'/').replace(/^\/?|\/?$/, '');
		}
		else
			this.cwd = "";
		this.dashboard = new Array();
		this.open = new Open(this.root);
		this.open.onauthenticate = function(challenge, result)
		{
			this.authenticate.challenge = challenge;
			if (this.onauthenticate != undefined)
				this.onauthenticate.call(this, challenge, result);
		}.bind(this);
		this.open.onnotfound = function(file)
		{
			if (this.onnotfound != undefined)
				this.onnotfound.call(this, file);
			else if (this.onerror != undefined)
				this.onerror.call(this, "File not found");
		}.bind(this);
		this.open.onerror = function(status)
		{
			if (this.onerror != undefined)
				this.onerror(status);
		}.bind(this);
		this.remove = new Remove(this.root);
		this.remove.onauthenticate = function(challenge, result)
		{
			this.authenticate.challenge = challenge;
			if (this.onauthenticate != undefined)
				this.onauthenticate.call(this, challenge, result);
		}.bind(this);
		this.remove.onerror = function(status)
		{
			if (this.onerror != undefined)
				this.onerror(status);
		}.bind(this);
		this.uploader = new UpLoader(this.root);
		this.onput = undefined;
		this.onprogress = undefined;
		this.uploader.onload = function(file)
		{
			var ret = true;
			if (this.onput != undefined)
				ret = this.onput.call(this, file);
			if (this.uploader.isready && (ret == true || ret == undefined))
				this.uploader.exec(this.authorization);
		}.bind(this);
		this.uploader.onauthenticate = function(challenge, result)
		{
			this.authenticate.challenge = challenge;
			if (this.onauthenticate != undefined)
				this.onauthenticate.call(this, challenge, result);
		}.bind(this);
		this.change = new Change(this.root);
		this.authenticate = new Authenticate("Basic");
		this.authenticate.onauthorization = function(user)
		{
			this.user = user;
			this.authorization = this.authenticate.authorization;
			this.configure(this.root+"/.config/ouistiti/ouishell.json", function()
				{
					if (this.onauthorization != undefined)
						this.onauthorization.call(this, this.user);
				});
		}.bind(this);
		this.authenticate.onauthenticate = function(challenge, result)
		{
			this.authenticate.challenge = challenge;
			if (this.onauthenticate != undefined)
				this.onauthenticate.call(this, challenge, result);
		}.bind(this);
		this.authenticate.onerror = function(status)
		{
			if (this.onerror != undefined)
				this.onerror(status);
		}.bind(this);
	}
	configure(url, callback)
	{
		const xhr = new XMLHttpRequest();

		xhr.onreadystatechange = function()
		{
			if (xhr.readyState === XMLHttpRequest.DONE)
			{
				if (xhr.status === 200)
				{
					var type = xhr.getResponseHeader("Content-Type");
					if (type == "text/json")
					{
						var data = JSON.parse(xhr.responseText.trim());
						if (data.directories != undefined)
						{
							this.user.directories = Object.assign(this.user.directories, data.directories);
						}
					}
				}
				if (callback)
					callback.call(this);
			}
		}.bind(this);
		xhr.open("GET", url, true);
		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
		xhr.send();
	}
	generateid()
	{
		var array = new Uint32Array(1);
		window.crypto.getRandomValues(array);
		return array[0];
	}
	login(user, password)
	{
		if (user != undefined)
		{
			this.authenticate.username = user;
			this.authenticate.password = password;
			this.authenticate.build();
		}
		this.authenticate.get();
	}
	logout()
	{
		this.authenticate.remove();
	}
	cd(directory)
	{
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		this.cwd = directory.replace(/\\/g,'/').replace(/^\/?|\/?$/, '');
		//.replace(/\/[^\/]*$/, '');
		if (this.oncompleted != undefined)
		{
			this.oncompleted(id);
		}
	}
	ls(directory)
	{
		var filename = undefined;
		if (directory == undefined)
		{
			directory = this.cwd;
		}
		else if (directory[0] != '/')
		{
			directory = this.cwd + directory;
		}
		const id = this.generateid();
		this.open.onload = function(result)
		{
			if (result.type == "text/json")
			{
				var reader = new FileReader();
				reader.onloadend = function (evt)
					{
						const array = new Uint8ClampedArray(evt.target.result);
						var result = new TextDecoder("utf-8").decode(array);
						var resultJson = JSON.parse(result);
						this.content = resultJson.content;
						if (this.onchange != undefined)
						{
							var i = this.content.length - 1;
							if (this.content[i].name == undefined)
							{
								this.content.splice(i, 1);
							}
							this.onchange(this.content);
						}
					}.bind(this);
				reader.readAsArrayBuffer(result);
			}
			else
			{
				alert("receive data type "+result.type);
			}
		}.bind(this);
		this.open.open(directory);
		var file = new Blob();
		file.name = "?timestamp="+id;
		this.open.set(file);
		this.open.exec(this.authorization);
		return id;
	}
	launch(file, mime)
	{
		var application = undefined;
		this.open.open(this.cwd);
		if (this.user != undefined)
		{
			var i;
			for (i = 0; i < this.user.mimes.length; i++)
			{
				var regexp = new RegExp(this.user.mimes[i].type);
				if (regexp.test(mime))
				{
					var path = location.pathname.replace(/\\/g,'/').replace(/\/[^\/]*$/, '').replace(/^\/?|\/?$/, '');
					application = "/"+path+"/"+this.user.mimes[i].appli;
					break;
				}
			}
		}
		if (application != undefined)
		{
			if (application.indexOf('?') == -1)
				application = application+"?";
			else
				application = application+"&";
			this.open.go(application,"root="+this.root+"&cwd="+this.cwd+"&file="+file);
		}
		else
			this.open.go(file,"");
	}
	rm(filename)
	{
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		this.remove.onload = function(file)
		{
			if (this.oncompleted != undefined)
			{
				this.oncompleted(id);
			}
		}.bind(this);
		var file = new Blob();
		file.name = filename;
		this.remove.open(this.cwd);
		this.remove.set(file);
		this.remove.exec(this.authorization);
		return id;
	}
	paste()
	{
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		if (this.dashboard.length > 0)
		{
			var copy = this.dashboard.shift();
			if (copy.type != undefined)
			{
				this.uploader.onupload = function(file)
				{
					if (file.cut == true)
					{
						this.remove.onload = function(file)
						{
							if (this.oncompleted != undefined)
							{
								this.oncompleted(id);
							}
						}.bind(this);
						this.remove.open(this.cwd);
						file.name = file.oldname;
						this.remove.set(file);
						this.remove.exec(this.authorization);
					}
					else
					{
						if (this.oncompleted != undefined)
						{
							this.oncompleted(id);
						}
					}
				}.bind(this);
				this.uploader.open(this.cwd);
				this.uploader.set(copy.file);
				this.uploader.exec(this.authorization);
			}
		}
		return id;
	}
	cp(filename, copyname, cut)
	{
		var file = new Blob();
		file.name = filename;
		file.newname = copyname;
		file.cut = cut;
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		this.open.onload = function(file)
		{
			if (file.newname != undefined)
			{
				this.uploader.onupload = function(file)
				{
					if (this.oncompleted != undefined)
					{
						this.oncompleted(id);
					}
				}.bind(this);
				this.uploader.open(this.cwd);
				file.name = file.newname;
				this.uploader.set(file);
				this.uploader.exec(this.authorization);
			}
			else
			{
				this.dashboard.unshift(file);
			}
		}.bind(this);
		this.open.open(this.cwd);
		this.open.set(file);
		this.open.exec(this.authorization);
		return id;
	}
	mv(oldname, newname)
	{
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		var file = new Blob();
		file.name = oldname;
		this.change.onload = function(file)
		{
			if (this.oncompleted != undefined)
			{
				this.oncompleted(id);
			}
		}.bind(this);
		this.change.open(this.cwd);
		this.change.set(file);
		var data = {
			cmd: "mv",
			arg: this.root + "/" + this.cwd + "/" + newname,
		};
		this.change.command(data);
		this.change.exec(this.authorization);
		
/*
		this.open.onload = function(file)
		{
			//consol.log("file "+file.name+" loaded");
			this.uploader.onupload = function(resultjson)
			{
				//consol.log("file "+file.name+" uploaded");
				this.remove.onload = function(file)
				{
					if (this.oncompleted != undefined)
					{
						this.oncompleted(id);
					}
				}.bind(this);
				this.remove.open(this.cwd);
				this.remove.set(fileold);
				this.remove.exec(this.authorization);
			}.bind(this);
			this.uploader.open(this.cwd);
			file.name = newname;
			this.uploader.set(file);
			this.uploader.exec(this.authorization);
		}.bind(this);
		this.open.open(this.cwd);
		this.open.set(fileold);
		this.open.exec(this.authorization);
*/
		return id;
	}
	mkdir(directory)
	{
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		this.uploader.onupload = function(resultjson)
		{
			if (this.oncompleted != undefined)
			{
				this.oncompleted(id);
			}
		}.bind(this);
		if (directory != undefined)
			this.uploader.open(this.cwd+"/"+directory);
		else
			this.uploader.open(this.cwd);
		this.uploader.set();
		this.uploader.exec(this.authorization);
		return id;
	}
	ln(filepath,link)
	{
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		this.change.onload = function(file)
		{
			if (this.oncompleted != undefined)
			{
				this.oncompleted(id);
			}
		}.bind(this);
		var file = new Blob();
		file.name = filepath;
		
		this.change.open(this.cwd);
		this.change.set(file);
		var linkpath;
		if (link[0] == '/')
			linkpath = link;
		else
			linkpath = this.root + "/" + this.cwd + "/" + link;
		var data = {
			cmd: "ln",
			arg: linkpath,
		};
		this.change.command(data);
		this.change.exec(this.authorization);
	}
	put(file)
	{
		const id = this.generateid();
		if (this.onbegin != undefined)
		{
			this.onbegin(id);
		}
		this.uploader.onupload = function(resultjson)
		{
			if (this.oncompleted != undefined)
			{
				this.oncompleted(id);
			}
			this.uploader.onprogress = undefined;
		}.bind(this);
		this.uploader.onerror = function(status)
		{
			if (this.onerror != undefined)
				this.onerror(status);
			if (this.oncompleted != undefined)
			{
				this.oncompleted(id);
			}
		}.bind(this);
		this.uploader.onprogress = function(loaded, total)
		{
			if (this.onprogress != undefined)
			{
				this.onprogress(id, (loaded / total) * 100, loaded, total);
			}
		}.bind(this);
		this.uploader.open(this.cwd);
		this.uploader.get(file);
		return id;
	}
};
