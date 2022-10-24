/**
var message = {
	scripts: [{
		name:"send2app",
		script:"this.contentWindow.postMessage(message, window.location.href);"
	}],
	cmdbar: [{
		buttons: [{
			id:"stop",
			glyphicon:"stop",
			name:"stop",
			click:"send2app(\'stop\')",
		},{
			id:"play",
			glyphicon:"play",
			name:"play",
			click:"send2app(\'play\')",
		}]
	}]
};
*/
class CmdBarControl {
	action = "initialize";
	scripts = [];
	cmdbar = undefined;
	menu = undefined;
	constructor(client, action) {
		if (typeof action === "string")
			this.action = action;
		switch (this.action) {
		case "remove":
		case "refresh":
			delete this.scripts;
		break;
		case "update":
		break;
		case "initialize":
			if (client) {
				this.scripts.push({
					name:"send2app",
					script:"this.postMessage(message, window.location.href);",
				});
			}
		break;
		}
	}
	addgroup(array) {
		if (array.length == 0)
			return;
		for (let button of array) {
			if (button.click == undefined)
				button.click = "send2app(\'"+button.name+"\')";
		}
		var group = { buttons:array};
		if (this.cmdbar == undefined)
			this.cmdbar = [];
		this.cmdbar.push(group);
	}
	addmenu(object) {
		if (object.buttons) {
			for (let button of object.buttons) {
				if (button.click == undefined)
					button.click = "send2app(\'"+button.name+"\')";
			}
		}
		if (object.click == undefined)
			object.click = "send2app(\'"+object.name+"\')";
		if (this.menu == undefined)
			this.menu = [];
		this.menu.push(object);
	}
	addscript(name, href, func) {
		if (this.scripts == undefined)
			return;
		var script = {
			name: name,
			href: href,
			};
		if (typeof func === "function") {
			var funcstring = func.toString()
				.replace(/\n/g, '')
				.replace(/\t/g, '');
			var re = new RegExp(name+"\\(message\\) {\(.*\)}");
			script.script = re.exec(funcstring)[1];
		}
		this.scripts.push(script);
	}
};

/**
 * create a command bar from object
 * manage cmdbar events with serialized scripts
 * 
 * API:
 * var cmdbar = {
 *    cmdbar: [{
 *      id: "button1",
 *      name: "download",
 *      glyphicon: "download",
 *      script: "download(\'test.jpeg\')",
 *    } , {
 *      id: "button2",
 *      name: "stop",
 *      glyphicon: "stop",
 *      script: "send2app(\'stop\')"
 *    }],
 *    scripts: [{
 *      name: "download",
 *      src: "/apps/js/download.js"
 *    } , {
 *      name: "send2app",
 *      script: "this.contentWindow.postMessage(message, window.location.href);"
 *    }]
 *  }
 * var cmdbar = new CmdBarServer('DOMcmdbarid','DOMmenuid'); //<div class="navbar-form navbar-header" id='DOMcmdbarid'></div>
 *                                                           //<ul class="nav navbar-nav" id='DOMmenuid'></ul>
 * cmdbar.attachFrame('DOMframeid'); //<iframe id='DOMframeid'></div>
 * cmdbar.load(cmdbar);
 */
class CmdBarServer {
	#cmdbarid = undefined;
	#menuid = undefined;
	#frameid = undefined;
	constructor(cmdbar, menu) {
		this.#cmdbarid = cmdbar;
		this.#menuid = menu;
	}
	attachFrame(frame) {
		this.#frameid = frame;
		$('#'+frame).attr('name',frame);
		window.addEventListener('message', function(event) {
			var apps = document.getElementById(this.#frameid);
			if (event.source != apps.contentWindow)
				return;
			this.load(event.data, this.#frameid)
		}.bind(this));
	}
	load(object, id) {
		var cmdbarid = undefined;
		if (object.id)
			id = object.id;
		if (id)
			cmdbarid = id+"_cmdbar";
		var menuid = undefined;
		if (id)
			menuid = id+"_menu";
		var $cmdbar = undefined;
		switch (object.action) {
		case "remove":
			if (object.id) {
				$('#'+object.id+'_cmdbar').remove();
				$('#'+object.id+'_menu').remove();
			}
			if (object.cmdbar && object.cmdbar.id) {
				var $cmdbar = $('#'+cmdbarid);
				if ($cmdbar.length == 0) {
					$cmdbar = $('#'+object.cmdbar.id);
				}
				$cmdbar.remove();
			}
			if (object.menu && object.menu.id) {
				var $menu = $('#'+menuid);
				if ($menu.length == 0) {
					$menu = $('#'+object.menu.id);
				}
				$menu.remove();
			}
		break;
		case "refresh":
			if (object.cmdbar) {
				if (cmdbarid)
					$cmdbar = $('#'+this.#cmdbarid).find("#"+cmdbarid);
				else
					$cmdbar = $('#'+this.#cmdbarid).child()[0];
				this.#refreshcmdbar($cmdbar, object.cmdbar);
			}
		break;
		case "update":
			if (object.cmdbar) {
				$cmdbar = this.#updatecmdbar(object.cmdbar,cmdbarid);
				$('#'+this.#cmdbarid).append($cmdbar);
			}
			if (object.menu) {
				var $menulist = $("#"+menuid);
				if ($menulist) {
					var $menu = this.#updatemenu(object.menu);
					$menulist.append($menu);
				}
			}
		break;
		default:
			if (object.cmdbar) {
				$cmdbar = this.#createcmdbar(object.cmdbar,cmdbarid);
				$('#'+this.#cmdbarid).append($cmdbar);
			}
			if (object.menu) {
				var $menulist = $("<ul></ul>");
				if (menuid)
					$menulist.attr('id', menuid);
				$menulist.addClass('navbar-nav');
				$menulist.addClass('navbar-nav-scroll');
				if (typeof object.menu.classes === "string")
					$menulist.addClass(object.menu.classes);
				else if (typeof object.menu.classes === "object") {
					for (newclass of object.menu.classes) {
						$menulist.addClass(newclass);
					}
				}
				for (let menu of object.menu) {
					var $menu = this.#createmenu(menu);
					$menulist.append($menu);
					this.#addclasses($menulist, menu.classes);
				}
				$('#'+this.#menuid).append($menulist);
				
			}
		}
		if (object.scripts) {
			this.#loadscripts(object.scripts);
		}
		if (object.theme) {
			if (typeof object.theme.navclass === "string") {
				let nav = $('#'+this.#menuid).parents("nav");
				nav.addClass(object.theme.navclass);
			}
			if (typeof object.theme.bodyclass === "string") {
				let body = $('body');
				body.addClass(object.theme.bodyclass);
			}
			if (typeof object.theme.background === "string") {
				let body = $('body');
				body.css('background-image', 'url("'+object.theme.background+'")');
			}
		}
	}
	cleanFrame() {
		$('#'+this.#frameid+'_cmdbar').remove();
		$('#'+this.#frameid+'_menu').remove();
	}
	#addclasses($element, classes) {
		if (classes && typeof classes === "string") {
			classes = classes.split(" ");
		}
		if (classes) {
			for (const newclass of classes) {
				if (newclass.indexOf('!') == 0) {
					$element.removeClass(newclass.substring(1));
				}
				else
					$element.addClass(newclass);
			}
		}
	}
	#loadscripts(scripts) {
		for (let script of scripts) {
			if (script.script) {
				//console.log("server: "+script.name+" {"+script.script+"}");
				if (window[script.name]) {
					delete window[script.name];
				}
				window[script.name] = new Function('message',script.script).bind(event.source);
			}
			if (script.src) {
				var DOMscript = document.createElement('script');
				DOMscript.src = script.src;
			}
		}
	}
	#createcmdbar(object, id) {
		var $oldcmdbar = $("#"+id);
		if ($oldcmdbar) {
			$oldcmdbar.remove();
		}
		return this.#updatecmdbar(object, id);
	}
	#updatecmdbar(object, id) {
		var $cmdbar = $("#"+id);
		if ($cmdbar.length == 0) {
			$cmdbar = $("<div class='btn-toolbar cmdbar' role='toolbar'></div>");
			$cmdbar.addClass('justify-content-between');
			$cmdbar.attr('id',id);
		}
		for (const elemt of object)
		{
			if (elemt.buttons)
				$cmdbar.append(this.#createcmdgroup(elemt.buttons, $cmdbar));
		}
		return $cmdbar;
	}
	#onclick (event) {
		var $button = $("#"+event.currentTarget.id);
		var funcstring = $button.data("click");
		//console.log("click on "+event.currentTarget.id);
		var func = new Function("event", funcstring);
		var bindingfunc = func.bind($button);
		bindingfunc(event);
	}
	#createcmdgroup(buttons, $cmdbar) {
		var $group = $("<div class='btn-group' role='group'></div>")
		for (const button of buttons) {
			var $button = $cmdbar.children("#"+button.id);
			if ($button.length == 0) {
				$button = $("<button type='button' class='action-btn btn btn-default' aria-expanded='false'></button>");
				$button.attr('id', button.id);
				if (typeof button.click === "string") {
					$button.off("click");
					$button.data("click", button.click);
					$button.on("click", this.#onclick.bind(this));
				}
			}
			this.#addclasses($button, button.classes);
			var $glyphicon = undefined;
			if (button.glyphicon) {
				$glyphicon = $("<span class='glyphicon glyphicon-"+button.glyphicon+"' aria-hidden='true'></span>");
				$button.append($glyphicon);
			}
			if (button.name) {
				var $title = $("<span>"+button.name+"</span>");
				if ($glyphicon != undefined)
					$title.addClass('visually-hidden');
				$button.append($title);
			}
			$group.append($button);
		}
		return $group;
	}
	#createmenu(object, id) {
		if (object.id)
			id = object.id;
		var $oldmenu = $("#"+id);
		if ($oldmenu) {
			$oldmenu.remove();
		}
		return this.#updatemenu(object, id);
	}
	#updatemenu(object,id) {
		var $menuli = $("#"+id);
		if ($menuli.length == 0) {
			$menuli = $("<li class='nav-item'></li>");
			if (id)
				$menuli.attr('id', id);
			this.#addclasses($menuli, object.classes);
		}
		var $menuitem = this.#createmenuli(object);
		$menuitem.attr('id', id+"_anchor");
		$menuitem.addClass('nav-link');
		$menuli.append($menuitem);
		$menuli.addClass('nav-item');
		if (object.buttons) {
			$menuitem.addClass('dropdown-toggle');
			$menuitem.attr('data-bs-toggle','dropdown');
			$menuli.addClass('dropdown');
			let $dropdown = this.#createdropdown(id+"_anchor", object.buttons);
			if (Array.isArray(object.classes) && object.classes.findIndex("order-last") != -1)
				$dropdown.addClass('dropdown-menu-end');
			if (typeof(object.classes) === "string" && object.classes.indexOf("order-last") != -1)
				$dropdown.addClass('dropdown-menu-end');
			$menuli.append($dropdown);
		}
		return $menuli;
	}
	#createdropdown(id, buttons) {
		var $dropdown = $("<ul></ul>");
		$dropdown.addClass('dropdown-menu');
		$dropdown.attr('aria-labelledby', id);
		for (let button of buttons) {
			var $menuli = $("<li></li>");
			this.#addclasses($menuli, button.classes);
			var $menuitem = this.#createmenuli(button);
			$menuitem.addClass('dropdown-item');
			$menuli.append($menuitem);
			$dropdown.append($menuli);
		}
		return $dropdown;
	}
	#createmenuli(object, classes) {
		var href = "#"
		if (object.href)
			href = object.href;
		var $anchor = undefined;
		$anchor = $("<a href='"+href+"' aria-expanded='false'>"+object.name+"</a>");
		if (href != "#" && this.#frameid) {
			$anchor.attr('target', this.#frameid);
		}
		if (typeof object.click == "string")
			$anchor.on("click", new Function("event", object.click));
		return $anchor;
	}
	#refreshcmdbar(cmdbar, object) {
		for (const elemt of object) {
			if (elemt.buttons) {
				this.#refreshcmdgroup(cmdbar, elemt.buttons);
			}
		}
	}
	#refreshcmdgroup(cmdbar, buttons) {
		for (const button of buttons) {
			var $button = undefined
			if (button.id)
				$button = $(cmdbar).find("#"+button.id);
			if ($button == undefined)
				continue;
			if (button.glyphicon) {
				$button.find('.glyphicon').removeClass().addClass("glyphicon glyphicon-"+button.glyphicon);
			}
			if (button.classes) {
				this.#addclasses($button, button.classes);
			}
		}
	}
};

class CmdBarClient {
	#listeners = [];
	#server = undefined;
	id = undefined
	constructor(listener, id) {
		this.id = id;
		if (listener)
			this.#listeners.push(listener);
		this.#server = window.parent;
		window.addEventListener('message', this.#listener.bind(this));
	}
	#listener(event) {
		var url = new URL(event.origin);
		if (url.host != window.location.host)
			return;
		for (let listener of this.#listeners) {
			listener(event.data);
		}
	}
	load(cmdbarcontrol, id, listener) {
		if (listener)
			this.#listeners.push(listener);
		if (cmdbarcontrol) {
			if (id)
				cmdbarcontrol.id = id;
			else if (this.id)
				cmdbarcontrol.id = this.id;
			this.#server.postMessage(cmdbarcontrol);
		}
	}
};
