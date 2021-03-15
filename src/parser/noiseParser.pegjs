{
const g = {
	s: 0,
	e: 0,
	rs: 0,
	re: 0,
	ss: 0,
	se: 0,
	es: 0,
	ee: 0
};

const util = {
	hasDuplicates: (arr) => {
		let vo = {};
		for (let i = 0; i < arr.length; ++i) {
			let v = arr[i];
			if (v in vo) { return true; }
			vo[v] = true;
		}
		return false;
	}
};

const errMsg = {
	// Below are validity rules specific to Noise Explorer and not to the Noise Protocol Framework.
	tooLongName: 'Noise 握手模式名目前只支持最多16个字符。',
	tooManyTokens: 'Noise 消息模式目前只支持最多8个令牌。',
	tooManyMessages: 'Noise 握手模式目前只支持最多8个消息模式。',
	moreThanOnePsk: 'Noise 握手模式目前只支持最多1个PSK。',
	// Below are validity rules which we are not exactly sure are shared by the Noise Protocol Framework (but likely are.)
	tokenOrderIncorrect: '公钥令牌在出现在涉及它们的 Diffie-Hellman 密钥交换之前，必须在消息中排序。',
	transportNotLast: 'Noise 握手模式只能在模式的最底部包含传输握手信息。',
	transportOnly: 'Noise 握手模式不能纯粹由传输消息组成。',
	unusedKeySent: 'Noise 握手模式不应包含随后在任何 Diffie-Hellman 密钥交换中都用不到的密钥交换操作。',
	// Below are validity rules shared by the Noise Protocol Framework.
	dupTokens: 'Noise 握手模式在同一消息传输 (flight) 中不得包含重复的令牌。',
	keySentMoreThanOnce: '每次握手时，操作者不得多次发送其静态公钥或临时公钥。',
	dhSentMoreThanOnce: '每次握手时，操作者不得多次执行同一 Diffie-Hellman 密钥交换。',
	wrongPskModifier: 'PSK 修改操作必须正确指出 PSK 令牌的位置。',
	wrongPskLocation: 'PSK 令牌必须出现在第一条握手信息的开头或结尾，或任何其他握手信息的结尾。',
	pskNotAtEndOfName: 'PSK 修改操作必须出现在 Noise 握手模式名的末尾。',
	wrongMessageDir: 'Noise 握手模式内的两端必须交替发送消息（发起者->响应者，发起者<-响应者），第一个消息必须由发起者发送。',
	dhWithUnknownKey: '操作者不能对不存在的密钥共享进行 Diffie-Hellman 操作。',
	seEeRule: '在 se 令牌之后，除非发起者在同时拥有 ee 令牌，否则其不得发送握手有效载荷或传输有效载荷。',
	ssEsRule: '在 ss 令牌之后，除非发起者在同时拥有 es 令牌，否则其不得发送握手有效载荷或传输有效载荷。',
	esEeRule: '在 es 令牌之后，除非发起者在同时拥有 ee 令牌，否则其不得发送握手有效载荷或传输有效载荷。',
	ssSeRule: '在 ss 令牌之后，除非发起者在同时拥有 se 令牌，否则其不得发送握手有效载荷或传输有效载荷。'
};

const check = {
	preMessages: (pattern) => {
		pattern.preMessages.forEach((preMessage) => {
			if (preMessage.tokens.indexOf('s') >= 0) {
				(preMessage.dir === 'send')? g.s++ : g.rs++;
			}
			if (preMessage.tokens.indexOf('e') >= 0) {
				(preMessage.dir === 'send')? g.e++ : g.re++;
			}
		});
	},
	messages: (pattern) => {
		if (pattern.messages.length > 8) {
			error(errMsg.tooManyMessages);
		}
		pattern.messages.forEach((message, i) => {
			if (
				((i % 2)  && (message.dir === 'send')) ||
				(!(i % 2) && (message.dir === 'recv'))
			) {
				error(errMsg.wrongMessageDir);
			}
			if (util.hasDuplicates(message.tokens)) {
				error(errMsg.dupTokens);
			}
			if (message.tokens.length > 8) {
				error(errMsg.tooManyTokens);
			}
			if (message.tokens.indexOf('s') >= 0) {
				if (((message.dir === 'send') && (
					(
						(message.tokens.indexOf('se') >= 0) &&
						(message.tokens.indexOf('se') < message.tokens.indexOf('s'))
					) || (
						(message.tokens.indexOf('ss') >= 0) &&
						(message.tokens.indexOf('ss') < message.tokens.indexOf('s'))
					)
				)) || ((message.dir === 'recv') && (
					(
						(message.tokens.indexOf('es') >= 0) &&
						(message.tokens.indexOf('es') < message.tokens.indexOf('s'))
					) || (
						(message.tokens.indexOf('ss') >= 0) &&
						(message.tokens.indexOf('ss') < message.tokens.indexOf('s'))
					)
				))) {
					error(errMsg.tokenOrderIncorrect);
				}
				(message.dir === 'send')? g.s++ : g.rs++;
			}
			if (message.tokens.indexOf('e') >= 0) {
				if (((message.dir === 'send') && (
					(
						(message.tokens.indexOf('es') >= 0) &&
						(message.tokens.indexOf('es') < message.tokens.indexOf('e'))
					) || (
						(message.tokens.indexOf('ee') >= 0) &&
						(message.tokens.indexOf('ee') < message.tokens.indexOf('e'))
					)
				)) || ((message.dir === 'recv') && (
					(
						(message.tokens.indexOf('se') >= 0) &&
						(message.tokens.indexOf('se') < message.tokens.indexOf('e'))
					) || (
						(message.tokens.indexOf('ee') >= 0) &&
						(message.tokens.indexOf('ee') < message.tokens.indexOf('e'))
					)
				))) {
					error(errMsg.tokenOrderIncorrect);
				}
				(message.dir === 'send')? g.e++ : g.re++;
			}
			if (message.tokens.indexOf('ss') >= 0) {
				g.ss++;
				if (
					(message.dir === 'send') &&
					(g.es === 0) &&
					(message.tokens.indexOf('es') < 0)
				) {
					error(errMsg.ssEsRule);
				}
				if (
					(message.dir === 'recv') &&
					(g.se === 0) &&
					(message.tokens.indexOf('se') < 0)
				) {
					error(errMsg.ssSeRule);
				}
			}
			if (message.tokens.indexOf('se') >= 0) {
				g.se++;
				if (
					(message.dir === 'send') &&
					(g.ee === 0) &&
					(message.tokens.indexOf('ee') < 0)
				) {
					error(errMsg.seEeRule);
				}
			}
			if (message.tokens.indexOf('es') >= 0) {
				g.es++;
				if (
					(message.dir === 'recv') &&
					(g.ee === 0) &&
					(message.tokens.indexOf('ee') < 0)
				) {
					error(errMsg.esEeRule);
				}
			}
			if (message.tokens.indexOf('ee') >= 0) {
				g.ee++;
			}
			if (
				(g.ss && (!g.s || !g.rs)) ||
				(g.se && (!g.s || !g.re)) ||
				(g.es && (!g.e || !g.rs)) ||
				(g.ee && (!g.e || !g.re))
		 	) {
				error(errMsg.dhWithUnknownKey);
			}
		});
		if (
			(g.s  && (!g.ss && !g.se)) ||
			(g.e  && (!g.es && !g.ee)) ||
			(g.rs && (!g.ss && !g.es)) ||
			(g.re && (!g.se && !g.ee))
		) {
			error(errMsg.unusedKeySent);
		}
		if  (
			(g.s > 1) || (g.e > 1) ||
			(g.rs > 1) || (g.re > 1)
		) {
			error(errMsg.keySentMoreThanOnce);
		}
		if  (
			(g.ee > 1) || (g.es > 1) ||
			(g.se > 1) || (g.ss > 1)
		) {
			error(errMsg.dhSentMoreThanOnce);
		}
	},
	psk: (pattern) => {
		let pskMods = pattern.name.match(/psk\d/g);
		if (!pskMods) {
			pattern.messages.forEach((message) => {
				if (message.tokens.indexOf('psk') >= 0) {
					error(errMsg.wrongPskModifier);
				}
			});
			return false;
		}
		if (pskMods.length > 1) {
			error(errMsg.moreThanOnePsk);
		}
		if (!/psk\d$/.test(pattern.name)) {
			error(errMsg.pskNotAtEndOfName);
		}
		pskMods.forEach((pskMod) => {
			pskMod = parseInt(pskMod.charAt(3), 10);
			if (pskMod > pattern.messages.length) {
				error(errMsg.wrongPskModifier);
			} else if (pskMod === 0) {
				let tokens = pattern.messages[pskMod].tokens;
				if (tokens.indexOf('psk') < 0) {
					error(errMsg.wrongPskModifier);
				} else if (tokens.indexOf('psk') > 0) {
					error(errMsg.wrongPskLocation);
				}
			} else {
				let tokens = pattern.messages[pskMod - 1].tokens;
				if (tokens.indexOf('psk') < 0) {
					error(errMsg.wrongPskModifier);
				} else if (tokens.indexOf('psk') !== (tokens.length - 1)) {
					(pskMod === 1)? error(errMsg.wrongPskModifier) : error(errMsg.wrongPskLocation);
				}
			}
		});
	},
	transportMessages: (pattern) => {
		let transportMessage = -1;
		pattern.messages.forEach((message, i) => {
			if (
				(message.tokens.length === 0) &&
				(transportMessage === -1)
			) {
				transportMessage = i;
			}
			if (
				(message.tokens.length > 0) &&
				(transportMessage >= 0) &&
				(i > transportMessage)
			) {
				error(errMsg.transportNotLast);
			}
		});
		if (pattern.messages[0].tokens.length === 0) {
			error(errMsg.transportOnly);
		}
	}
};
}

Pattern =
	Name:Identifier ':' _
    PreMessages:PreMessages? _
    Messages:Messages {
		let pattern = {
			name: Name,
			preMessages: [],
			messages: Messages
		};
		pattern.preMessages = PreMessages? PreMessages : [];
		check.preMessages(pattern);
		check.messages(pattern);
		check.psk(pattern);
		check.transportMessages(pattern);
    	return pattern;
    }

Identifier =
	[a-zA-Z0-9]+ {
		if (text().length > 16) {
			error(errMsg.tooLongName);
		} else {
			return text();
		}
	}

_  =
	[ \t\n\r]* {
		return text();
	}

Ellipsis =
	_ '...' _ {
		return (text().length > 0)
	}

Arrow =
	'->' {
		return 'send';
	} /
	'<-' {
		return 'recv';
	}

Token =
	('psk' / 'ss' / 'se' / 'es' / 'ee' / 's' / 'e') {
		return text();
	}

PreMessageToken =
	('e, s' / 'e' / 's') {
		return text();
	}
    
Tokens =
	(Token (', ' / ','))* Token {
		let normalized = text().replace(/\,\s/g, ',');
		return normalized.split(',');
	}
    
PreMessage =
	_ Dir:Arrow _ Token:PreMessageToken {
		return {
			type: 'PreMessage',
			dir: Dir,
			tokens: Token
		};
	}

PreMessages =
	PreMessages:((PreMessage _) (PreMessage _)? Ellipsis) {
		let pMsg = [PreMessages[0][0]];
		if (!Array.isArray(PreMessages[1])) {
			// Do nothing.
		} else if (PreMessages[1][0].dir === 'recv') {
			pMsg.push(PreMessages[1][0]);
		} else if (PreMessages[1][0].dir === 'send') {
			pMsg.unshift(PreMessages[1][0]);
		}
		return pMsg;
	}
    
Message =
	_ Dir:Arrow _ Tokens:Tokens? {
		return {
			type: 'Message',
			dir: Dir,
			tokens: Tokens? Tokens : []
		};
	}

Messages =
	Messages:(Message _)+ {
		let msgs = [];
		Messages.forEach((msg, i) => {
			msgs.push(msg[0]);
		});
		return msgs;
	}