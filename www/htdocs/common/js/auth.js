function getCook(cookiename)
{
	// Get name followed by anything except a semicolon
	var cookiestring=RegExp(cookiename+"=[^;]+").exec(document.cookie);
	// Return everything after the equal sign, or an empty string if the cookie name not found
	return decodeURIComponent(!!cookiestring ? cookiestring.toString().replace(/^[^=]+./,"") : "");
}

class Auth
{
  	constructor(url)
	{
		this.token = getCook("X-Auth-Token");
		if (url == undefined)
			this.url = "/token";
		else
			this.url = url;
	}
	logout()
	{
		if (this.token != undefined && this.token.length > 0)
		{
			document.cookie = "X-Auth-Token=";
			document.cookie = "Authorization=";
		}
	}
	check()
	{
		var headers = {
			"X-Requested-With": "XMLHttpRequest",
		};
		if (this.token != undefined && this.token.length > 0)
				headers["X-Auth-Token"] = this.token;
		this.request = $.ajax({
			type: "GET",
			url: this.url,
			xhrFields: {
				withCredentials: true
			},
			headers : headers,
			success: function(data, status, request) {
				this.user = request.getResponseHeader("X-Remote-User");
				this.group = request.getResponseHeader("X-Remote-Group");
				if (this.onPermission != undefined)
					this.onPermission(this.user, this.group);
			}.bind(this),
			error: function(request, textStatus, errorThrown) {
				this.user = request.getResponseHeader("X-Remote-User");
				this.group = request.getResponseHeader("X-Remote-Group");
				if (this.onPermission != undefined)
					this.onPermission(this.user, this.group);
			}.bind(this),
		});
	}
}
