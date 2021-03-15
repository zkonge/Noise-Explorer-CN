const NOISEREADER = {
	read: () => { },
	render: () => { }
};

(() => {

	const util = {
		abc: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'],
		seq: [
			'一', '二', '三', '四',
			'五', '六', '七', '八'
		]
	};

	const preMessagesSendStatic = (pattern) => {
		let r = false;
		pattern.preMessages.forEach((preMessage) => {
			if (
				(preMessage.dir === 'send') &&
				(/s/.test(preMessage.tokens))
			) {
				r = true;
			}
		});
		return r;
	};

	const preMessagesRecvStatic = (pattern) => {
		let r = false;
		pattern.preMessages.forEach((preMessage) => {
			if (
				(preMessage.dir === 'recv') &&
				(/s/.test(preMessage.tokens))
			) {
				r = true;
			}
		});
		return r;
	};

	const messagesSendStatic = (pattern) => {
		let r = -1;
		pattern.messages.forEach((message, i) => {
			if (
				(message.dir === 'send') &&
				(message.tokens.indexOf('s') >= 0)
			) {
				r = i;
			}
		});
		return r;
	};

	const messagesRecvStatic = (pattern) => {
		let r = -1;
		pattern.messages.forEach((message, i) => {
			if (
				(message.dir === 'recv') &&
				((message.tokens.indexOf('s') >= 0))
			) {
				r = i;
			}
		});
		return r;
	};

	const messagesPsk = (pattern) => {
		let r = -1;
		for (let i = 0; i < pattern.messages.length; i++) {
			if (pattern.messages[i].tokens.indexOf('psk') >= 0) {
				r = i;
				break;
			}
		}
		return r;
	};

	const readRules = {
		rawResult: /^RESULT.+(is false|is true|cannot be proved)\.$/
	};

	const htmlTemplates = {
		sendMessage: (offset, msg, tokens, authentication, confidentiality) => {
			return [
				`<line data-seclevel="${confidentiality}" x1="1" x2="248" y1="${offset}" y2="${offset}"></line>`,
				`<polyline data-seclevel="${confidentiality}" points="237 ${offset - 10} 248 ${offset} 237 ${offset + 10}"></polyline>`,
				`<circle data-seclevel="${authentication}" cx="17" cy="${offset}" r="15"></circle>`,
				`<text class="msg" x="16" y="${offset + 5}">${msg}</text>`,
				`<text class="tokens" x="120" y="${offset - 8}">${tokens}</text>`,
			].join('\n\t\t\t\t\t');
		},
		recvMessage: (offset, msg, tokens, authentication, confidentiality) => {
			return [
				`<line data-seclevel="${confidentiality}" x1="2" x2="250" y1="${offset}" y2="${offset}"></line>`,
				`<polyline data-seclevel="${confidentiality}" points="12 ${offset - 10} 2 ${offset} 12 ${offset + 10}"></polyline>`,
				`<circle data-seclevel="${authentication}" cx="234" cy="${offset}" r="15"></circle>`,
				`<text class="msg" x="233" y="${offset + 5}">${msg}</text>`,
				`<text class="tokens" x="120" y="${offset - 8}">${tokens}</text>`,
			].join('\n\t\t\t\t\t');
		},
		sendPreMessage: (offset, tokens) => {
			return [
				`<line x1="1" x2="248" y1="${offset}" y2="${offset}"></line>`,
				`<polyline points="237 ${offset - 10} 248 ${offset} 237 ${offset + 10}"></polyline>`,
				`<text class="tokens" x="120" y="${offset - 8}">${tokens}</text>`,
			].join('\n\t\t\t\t\t');
		},
		recvPreMessage: (offset, tokens) => {
			return [
				`<line x2="248" y1="${offset}" y2="${offset}"></line>`,
				`<polyline  points="10 ${offset - 10} 1 ${offset} 10 ${offset + 10}"></polyline>`,
				`<text class="tokens" x="120" y="${offset - 8}">${tokens}</text>`,
			].join('\n\t\t\t\t\t');
		},
		ellipsis: (offset) => {
			return [
				`\n\t\t\t\t<text class="ellipsis" x="120" y="${offset}">...</text>`,
			].join('\n');
		},
		analysisPreMessage: (dir, tokens) => {
			let who = (dir === 'send') ? '发起者' : '响应者';
			let whom = (dir === 'recv') ? '发起者' : '响应者';
			let phrases = {
				'e, s': `${who}被初始化时，使用的是本次会话独有的预共享临时密钥和预共享的静态密钥，后者被假定为${whom}预先认证的临时钥匙。`,
				'e': `在${who}初始化的时候，会使用一个预共享的临时密钥，并将其提供给${whom}。这个密钥被认为是未经认证的。`,
				's': `${who}用预共享的长期静态密钥进行初始化，假定${whom}z可信信道上预先进行了认证。`
			};
			return `<p>${phrases[tokens]}</p> \n\t\t\t`;
		},
		analysisMessage: (name, abc, dir, tokens, authentication, confidentiality, sanity) => {
			let who = (dir === 'send') ? '发起者' : '响应者';
			let whom = (dir === 'recv') ? '发起者' : '响应者';
			let authPhrases = {
				0: `不受益于<em>发送者认证</em>，不提供<em>信息完整性</em>。它可能是由任何一方发送的，包括主动攻击者`,
				1: `受益于<em>接收者认证</em>，但<em>容易受到密钥泄露假冒</em>的影响。如果${whom}的长期私钥被泄露，这种认证就会被伪造。但是，如果${who}与另一个被泄露的${whom}进行单独的会话，这个另外的会话可以被用来伪造这个会话中${whom}对这个消息的认证`,
				2: `受益于<em>发送者认证</em>，并<em>抗密钥泄露冒充</em>。假设相应的私钥是安全的，这种认证是无法伪造的。但是，如果${who}与另外一个被泄露的${whom}进行了单独的会话，那么这个另外的会话就可以用来伪造这个会话中${whom}对这个消息的认证`,
				3: `受益于<em>发送者和接收者的接收认证</em>，但<em>易受密钥泄露冒充的影响</em>。如果${whom}的长期私钥被泄露，这种认证就会被伪造。`,
				4: "受益于<em>发送者和接收者认证</em>，并<em>抗密钥泄露冒充</em>。假设相应的私人钥匙是安全的，这种认证是无法伪造的。"
			};
			let confPhrases = {
				0: "即使面对纯被动的攻击者，信息内容也不能从<em>信息保密中获益，任何<em>前向保密</em>都是不可能的",
				1: "信息内容受益于一些<em>信息保密</em>和一些<em>转发保密</em>，但不足以抵御任何主动攻击者",
				2: `消息内容得益于<em>消息保密</em>和一些<em>前向保密</em>：${whom}的长期私钥泄露，即使在以后的日子里，也会导致消息内容被攻击者解密`,
				3: `在被动攻击者的情况下，消息内容受益于<em>消息保密</em>和<em>弱前向保密</em>：如果${who}的长期静态密钥之前被泄露，那么${whom}的长期静态密钥后来被泄露，就会导致消息内容被攻击者解密`,
				4: `在主动攻击者的情况下，消息内容受益于<em>消息保密</em>和<em>弱前向保密</em>：如果${who}的长期静态密钥之前被泄露，那么${whom}的长期静态密钥后来被泄露，就会导致消息内容被主动攻击者解密，如果该攻击者在会话中也伪造了${whom}的临时密钥`,
				5: `消息内容得益于<em>消息保密</em>和<em>强大的前向保密</em>：如果临时私钥是安全的且${whom}不是主动攻击者冒充的，消息内容就不能被解密`,
			};
			let sanPhrases = {
				true: ``,
				false: `<strong>该结果的真实性无法验证。</strong>`
			};
			let phrase = [
				`\n\t\t\t<h3>消息 ${abc.toUpperCase()} <a href="/patterns/${name}/${abc.toUpperCase()}.html" class="detailedAnalysis">显示分析细节</a></h3>`,
				`<p>消息 ${abc.toUpperCase()}, 由 ${who} 发送, ${authPhrases[authentication]}. ${confPhrases[confidentiality]}. ${sanPhrases[sanity]} <span class="resultNums">${authentication},${confidentiality}</span></p>`
			].join('\n\t\t\t');
			return phrase;
		},
		detailed: {
			sendMessage: (msg, tokens, authentication, confidentiality) => {
				return [
					`<line data-seclevel="${confidentiality}" x1="1" x2="500" y1="70" y2="70"></line>`,
					`<polyline data-seclevel="${confidentiality}" points="480,50 500,70 480,90"></polyline>`,
					`<circle data-seclevel="${authentication}" cx="29" cy="70" r="25"></circle>`,
					`<text class="msg" x="29" y="77">${msg}</text>`,
					`<text class="tokens" x="240" y="50">${tokens}</text>`
				].join('\n\t\t\t\t\t');
			},
			recvMessage: (msg, tokens, authentication, confidentiality) => {
				return [
					`<line data-seclevel="${confidentiality}" x1="5" x2="499" y1="70" y2="70"></line>`,
					`<polyline data-seclevel="${confidentiality}" points="25,50 5,70 25,90"></polyline>`,
					`<circle data-seclevel="${authentication}" cx="471" cy="70" r="25"></circle>`,
					`<text class="msg" x="471" y="77">${msg}</text>`,
					`<text class="tokens" x="240" y="50">${tokens}</text>`
				].join('\n\t\t\t\t\t');
			},
			intro: (name, abc, seq, dir) => {
				let who = (dir === 'send') ? '发起者' : '响应者';
				let whom = (dir === 'recv') ? '发起者' : '响应者';
				return `<p>消息 <span class="mono">${abc.toUpperCase()}</span> 是在 <span class="mono">${name}</span> Noise 握手模式中的第 ${seq} 条消息。是由${who}发给${whom}的。 在此详细分析中，我们试图给您一些关于此消息背后协议逻辑的见解。这里给出的见解并不能完全扩展到完全说明形式化模型所进行的确切的状态转换，但至少进行了非正式的描述，以帮助说明消息 <span class="mono">${abc.toUpperCase()}</span> 如何影响协议。</p>`;
			},
			tokenTxt: (abc, dir, write, token) => {
				let who = (dir === 'send') ? '发起者' : '响应者';
				let whom = (dir === 'recv') ? '发起者' : '响应者';
				let letfunName = write ? `writeMessage` : `readMessage`;
				let stateFuns = {
					mixKey: (dir, dh) => {
						let dhDesc = '';
						switch (dh) {
							case 'e, re':
								dhDesc = `临时密钥与响应者的临时密钥`;
								break;
							case 'e, rs':
								dhDesc = `临时密钥与响应者的静态密钥`;
								break;
							case 's, re':
								dhDesc = `静态密钥与响应者的临时密钥`;
								break;
							case 's, rs':
								dhDesc = `静态密钥与响应者的静态密钥`;
								break;
						};
						return `<span class="mono">mixKey</span>，使用现有的<span class="mono">SymmetricState</span>密钥和从发起者的 ${dhDesc} 计算出的 Diffie-Hellman <span class="mono">dh(${dh})</span> 作为输入，调用HKDF函数。`;
					},
					mixHash: (dir) => {
						return `<span class="mono">mixHash</span>，将新的密钥哈希到会话哈希中。`;
					},
					mixKeyAndHash: (dir) => {
						return `<span class="mono">mixKeyAndHash</span>，将 PSK 值混合并哈希到状态中，然后从结果中初始化一个新的状态种子。`;
					},
					encryptAndHash: (dir, write) => {
						return `<span class="mono">encryptAndHash</span>，被在静态公钥上调用。如果发送者和接收者之间事先建立了任何 Diffie-Hellman 共享密钥，这将允许${who}以某种程度的保密性来传达他们的长期身份。`
					},
				};
				let verb = (token.length > 1) ?
					'计算' : (write ? '发送' : '接收');
				let desc = (() => {
					let p = `一个由发起者产生的 Diffie-Hellman 共享密钥`;
					switch (token) {
						case 'e':
							return `一个新的临时密钥共享`;
							break;
						case 's':
							return `一个静态密钥共享`;
							break;
						case 'ee':
							return `${p} 临时密钥与响应者的临时密钥`;
							break;
						case 'es':
							return `${p} 临时密钥与响应者的静态密钥`;
							break;
						case 'se':
							return `${p} 静态密钥与响应者的临时密钥`;
							break;
						case 'ss':
							return `${p} 静态密钥与响应者的静态密钥`;
							break;
						case 'psk':
							return `增加了一个预共享对称密钥的新的会话密钥`;
							break;
					}
				})();
				let res = [
					`<ul>`,
					`<li><span class="mono">${token}</span>：表示${write ? who : whom}是${verb} ${desc}作为这个消息的一部分。此令牌将以下状态转换添加到 <span class="mono">${letfunName}_${abc}</span>：</li>`,
					`<li><ul>`
				];
				switch (token) {
					case 'e':
						res = res.concat([
							`<li>${stateFuns.mixHash(dir)}</li>`
						]);
						break;
					case 's':
						res = res.concat([
							`<li>${stateFuns.encryptAndHash(dir, true)}</li>`
						]);
						break;
					case 'ee':
						res = res.concat([
							`<li>${stateFuns.mixKey(dir, 'e, re')}</li>`
						]);
						break;
					case 'es':
						res = res.concat([
							`<li>${stateFuns.mixKey(dir, 'e, rs')}</li>`
						]);
						break;
					case 'se':
						res = res.concat([
							`<li>${stateFuns.mixKey(dir, 's, re')}</li>`
						]);
						break;
					case 'ss':
						res = res.concat([
							`<li>${stateFuns.mixKey(dir, 's, rs')}</li>`
						]);
						break;
					case 'psk':
						res = res.concat([
							`<li>${stateFuns.mixKeyAndHash(dir)}</li>`
						]);
						break;
				}
				res.push('</ul></li></ul>');
				return res;
			},
			analysisTxt: (name, abc, seq, dir, write, letfun, tokens) => {
				let who = (dir === 'send') ? '发起者' : '响应者';
				let whom = (dir === 'recv') ? '发起者' : '响应者';
				let verb = write ? '发送中的' : '接受中的';
				let res = [
					`<h3>${verb[0].toUpperCase()}${verb.substr(1)} 消息 <span class="mono">${abc.toUpperCase()}</span></h3>`,
					`<p>在应用Π计算的过程中，发起者过程使用以下函数准备消息：<span class="mono">${abc.toUpperCase()}</span>。</p>`,
					`<p class="proverif">`
				];
				res = res.concat(letfun.split('\n'));
				res.push(`</p>`);
				if (tokens.length) {
					res = res.concat([
						`<h4>令牌被${write ? who : whom}处理的方式：</h4>`
					]);
					tokens.forEach((token) => {
						res = res.concat(htmlTemplates.detailed.tokenTxt(abc, dir, write, token))
					});
				} else {
					res = res.concat([
						`由于消息<span class="mono">${abc.toUpperCase()}</span>不包含任何令牌，因此它被认为是纯粹的“应用数据”类型消息，旨在传输被加密的有效载荷。`
					]);
				};
				if (tokens.indexOf('s') < 0) {
					res.push(`<p>如果静态公钥作为此消息的一部分进行了通信，那么它将被加密为 <span class="mono">ciphertext1</span>。然而，由于发起者在这里没有传递静态公钥，因此该值将被留为空值。`);
				}
				res.push(`<p>消息<span class="code">${abc.toUpperCase()}</span>的载荷被建模为函数<span class="mono">msg_a(发起者身份, 响应者身份, 会话ID)</span>的输出，被加密为<span class="mono">ciphertext2</span>。这将调用以下操作：</p><ul>`)
				if (write) {
					res.push(`<li><span class="mono">encryptAndHash</span> 在有效载荷上执行带有附加数据的验证加密(AEAD)，并将会话哈希作为附加数据(<span class="mono">encryptWithAd</span>)和<span class="mono">mixHash</span>，它将加密后的有效载荷哈希到下一个会话哈希中。</li>`)
				} else {
					res.push(`<li><span class="mono">decryptAndHash</span> 在有效载荷上执行带有附加数据的验证解密(AEAD)，并将会话哈希作为附加数据(<span class="mono">decryptWithAd</span>)和<span class="mono">mixHash</span>，它将加密后的有效载荷哈希到下一个会话哈希中。</li>`);
				}
				res.push('</ul>');
				return res.join('\n');
			}
		}
	};

	const getResultsTemplate = (rawResults) => {
		let resultsTemplate = {
			sanity: false
		};
		let msg = {
			authentication: {
				sanity: false,
				one: false,
				two: false,
				three: false,
				four: false
			},
			confidentiality: {
				sanity: false,
				one: false,
				two: false,
				thour: false,
				five: false
			}
		};
		let rawResultsStr = rawResults.join('\n');
		util.abc.forEach((abc) => {
			let stage = new RegExp(`stagepack_${abc}`);
			if (stage.test(rawResultsStr)) {
				resultsTemplate[abc] = JSON.parse(JSON.stringify(msg));
			}
		});
		return resultsTemplate;
	};

	const getRawResults = (pvOutput) => {
		let lines = pvOutput.split('\n');
		let rawResults = [];
		lines.forEach((line) => {
			if (readRules.rawResult.test(line)) {
				rawResults.push(line);
			}
		});
		return rawResults;
	};

	const getMsgAbc = (rawResult) => {
		if (rawResult.match(/stagepack_\w/)) {
			return rawResult.match(/stagepack_\w/)[0][10];
		}
		if (rawResult.match(/msg_\w/)) {
			return rawResult.match(/msg_\w/)[0][4];
		}
		throw new Error('getMsgAbc failure.');
	};

	const getAuthentication = (msgActive) => {
		if (!msgActive.authentication.one) {
			return 0;
		}
		if (!msgActive.authentication.two) {
			return 1;
		}
		if (!msgActive.authentication.three) {
			return 2;
		}
		if (!msgActive.authentication.four) {
			return 3;
		}
		return 4;
	};

	const getConfidentiality = (msgActive, msgPassive) => {
		if (!msgPassive.confidentiality.two) {
			return 0;
		}
		if (!msgActive.confidentiality.two) {
			return 1;
		}
		if (!msgPassive.confidentiality.thour) {
			return 2;
		}
		if (!msgActive.confidentiality.thour) {
			return 3;
		}
		if (!msgActive.confidentiality.five) {
			return 4;
		}
		return 5;
	};

	const well = (rawResult) => {
		if (rawResult.endsWith('is true.')) {
			return true;
		}
		return false;
	};

	const read = (pvOutput) => {
		let rawResults = getRawResults(pvOutput);
		let readResults = getResultsTemplate(rawResults);
		rawResults.forEach((rawResult, i) => {
			let isTrue = well(rawResult);
			if (i === rawResults.length - 1) {
				readResults.sanity = !isTrue;
			} else {
				let abc = getMsgAbc(rawResult);
				let r = i % 9;
				if (r === 0) {
					readResults[abc].authentication.sanity = !isTrue;
				} else if (r === 1) {
					readResults[abc].authentication.one = isTrue;
				} else if (r === 2) {
					readResults[abc].authentication.two = isTrue;
				} else if (r === 3) {
					readResults[abc].authentication.three = isTrue;
				} else if (r === 4) {
					readResults[abc].authentication.four = isTrue;
				} else if (r === 5) {
					readResults[abc].confidentiality.sanity = !isTrue;
				} else if (r === 6) {
					readResults[abc].confidentiality.two = isTrue;
				} else if (r === 7) {
					readResults[abc].confidentiality.thour = isTrue;
				} else if (r === 8) {
					readResults[abc].confidentiality.five = isTrue;
				}
			}
		});
		return [readResults, rawResults];
	};

	const render = (
		pattern,
		readResultsActive, readResultsPassive,
		rawResultsActive, rawResultsPassive
	) => {
		let arrowSvg = [];
		let analysisTxt = [];
		let offset = 30;
		let offsetIncrement = 160;
		let totalHeight = 30;
		if (pattern.preMessages.length) {
			pattern.preMessages.forEach((preMessage) => {
				arrowSvg.push(htmlTemplates[`${preMessage.dir}PreMessage`](
					offset, preMessage.tokens
				));
				offset = offset + offsetIncrement;
				totalHeight = totalHeight + offsetIncrement;
				analysisTxt.push(htmlTemplates.analysisPreMessage(
					preMessage.dir, preMessage.tokens
				));
			});
			arrowSvg.push(htmlTemplates.ellipsis(offset));
			offset = offset + offsetIncrement;
			totalHeight = totalHeight + offsetIncrement;
		}
		pattern.messages.forEach((message, i) => {
			let abc = util.abc[i];
			let authentication = 0;
			let confidentiality = 0;
			let sanity = false;
			if (
				readResultsActive[abc] &&
				readResultsPassive[abc]
			) {
				authentication = getAuthentication(
					readResultsActive[abc]
				);
				confidentiality = getConfidentiality(
					readResultsActive[abc],
					readResultsPassive[abc]
				);
				sanity = (
					readResultsActive[abc].authentication.sanity &&
					readResultsActive[abc].confidentiality.sanity &&
					readResultsActive.sanity
				);
				analysisTxt.push(htmlTemplates.analysisMessage(
					pattern.name,
					abc, message.dir, message.tokens,
					authentication, confidentiality, sanity
				));
			}
			arrowSvg.push(htmlTemplates[`${message.dir}Message`](
				offset, util.abc[i],
				message.tokens.join(', '),
				authentication,
				confidentiality
			));
			offset = offset + offsetIncrement;
			totalHeight = totalHeight + offsetIncrement;
			totalHeight = totalHeight + (((authentication === 1) || (authentication === 2)) ? 50 : 0);
			totalHeight = totalHeight + ((confidentiality > 2) ? 40 : 0);
		});
		return {
			arrowSvg: arrowSvg.join('\n'),
			analysisTxt: analysisTxt.join('\n'),
			totalHeight: totalHeight
		};
	};

	const renderDetailed = (
		activeModel, pattern, message,
		readResultsActive, readResultsPassive,
		rawResultsActive, rawResultsPassive
	) => {
		let abc = util.abc[message];
		let seq = util.seq[message];
		let dir = pattern.messages[message].dir;
		let who = (dir === 'send') ? 'alice' : 'bob';
		let whom = (dir === 'send') ? 'bob' : 'alice';
		let tokens = pattern.messages[message].tokens;
		let sends = preMessagesSendStatic(pattern) ? 0 : messagesSendStatic(pattern);
		let recvs = preMessagesRecvStatic(pattern) ? 0 : messagesRecvStatic(pattern);
		let hasPsk = (messagesPsk(pattern) >= 0) && (messagesPsk(pattern) <= message);
		let arrowSvg = [];
		let analysisTxt = [];
		let writeMessageRegExp = new RegExp(`letfun writeMessage_${abc}[^.]+\.`, '');
		let readMessageRegExp = new RegExp(`letfun readMessage_${abc}[^.]+\.`, '');
		let writeMessage = activeModel.match(writeMessageRegExp)[0];
		let readMessage = activeModel.match(readMessageRegExp)[0];
		let authentication = getAuthentication(readResultsActive[abc]);
		let confidentiality = getConfidentiality(readResultsActive[abc], readResultsPassive[abc]);
		if (pattern.messages[message].dir === 'send') {
			arrowSvg.push(htmlTemplates.detailed.sendMessage(
				abc, tokens.join(', '), authentication, confidentiality
			));
		} else {
			arrowSvg.push(htmlTemplates.detailed.recvMessage(
				abc, tokens.join(', '), authentication, confidentiality
			));
		}
		let longTermKeys = (() => {
			let r = ['', ''];
			if (who === 'alice') {
				if (sends >= 0) {
					r[0] = `${r[0]}静态密钥`;
				}
				if (recvs >= 0) {
					r[1] = `${r[1]}静态密钥`;
				}
			}
			if (who === 'bob') {
				if (sends >= 0) {
					r[1] = `${r[1]}静态密钥`;
				}
				if (recvs >= 0) {
					r[0] = `${r[0]}静态密钥`;
				}
			}
			r.forEach((v, i) => {
				if (hasPsk && (r[i].length > 0)) {
					r[i] = `${r[i]} 与 PSK`;
				} else if (hasPsk) {
					r[i] = `${r[i]}PSK`;
				} else if (r[i].length === 0) {
					r[i] = '未使用的长期密钥';
				}
			});
			return r;
		})();
		let queryExplanations = {
			authentication: ['',
				`在这个查询中，我们测试<em>发送者身份认证</em>和<em>消息完整性</em>。如果${whom[0].toUpperCase()}${whom.substr(1)}收到${who[0].toUpperCase()}${who.substr(1)}的有效消息，那么${who[0].toUpperCase()}${who.substr(1)}一定是将该消息发送给了<em>某人</em>，或者${who[0].toUpperCase()}${who.substr(1)}在会话开始之前，他们的${longTermKeys[0]}就已经泄露了，或者${whom[0].toUpperCase()}${whom.substr(1)}在会话开始之前，他们的${longTermKeys[1]}就已经泄露了`,
				`在这个查询中，我们测试<em>发送者身份认证</em>与其是否抵抗<em>假冒密钥</em>。如果${whom[0].toUpperCase()}${whom.substr(1)}收到${who[0].toUpperCase()}${who.substr(1)}的有效消息，那么${who[0].toUpperCase()}${who.substr(1)}一定是将该消息发送给了<em>某人</em>，或者${who[0].toUpperCase()}${who.substr(1)}在会话开始之前，他们的${longTermKeys[1]}已经被泄露了。`,
				`在这个查询中，我们测试<em>发送者和接收者的身份验证</em>以及<em>消息的完整性</em>。如果${whom[0].toUpperCase()}${whom.substr(1)}收到${who[0].toUpperCase()}${who.substr(1)}发来的有效消息，那么${who[0].toUpperCase()}${who.substr(1)}一定是向<em>${whom[0].toUpperCase()}${whom.substr(1)}，或者${who[0].toUpperCase()}${who.substr(1)}在会话开始之前，他们的${longTermKeys[0]}就已经被泄露了，或者${whom[0].toUpperCase()}${whom.substr(1)}在会话开始之前，他们的${longTermKeys[1]}就已经被泄露了。`,
				`在这个查询中，我们测试<em>发送者和接收者的身份验证</em>以及是否抵抗<em>假冒密钥</em>。如果${whom[0].toUpperCase()}${whom.substr(1)}收到${who[0].toUpperCase()}${who.substr(1)}的有效消息，那么${who[0].toUpperCase()}${who.substr(1)}一定是将该消息发送给<em>${whom[0].toUpperCase()}${whom.substr(1)}专门发送了该消息</em>，或者${who[0].toUpperCase()}${who.substr(1)}在会话开始之前，他们的${longTermKeys[0]}已经被泄露了`
			],
			confidentiality: ['',
				`在这个查询中，我们通过检查被动攻击者是否只能通过在协议会话之前或之后破坏${whom[0].toUpperCase()}${whom.substr(1)}的${longTermKeys[1]}，来测试<em>消息保密性</em>。`,
				`在这个查询中，我们测试<em>消息保密性</em>，检查主动攻击者是否只能通过在协议会话之前或之后破坏${whom[0].toUpperCase()}${whom.substr(1)}的${longTermKeys[1]}来检索有效载荷的明文。`,
				`在这个查询中，我们通过检查被动攻击者是否只能通过破坏${whom[0].toUpperCase()}${whom.substr(1)}的${whom.substr(1)}来检索有效载荷明文来测试<em>前向保密性</em>。在协议会话之前后的任何时候与${who[0].toUpperCase()}${who.substr(1)}的${longTermKeys[0]}一起进行检索。`,
				`在这个查询中，我们通过检查主动攻击者是否只能通过破坏${whom[0].toUpperCase()}${whom.substr(1)}的${whom.substr(1)}来检索有效载荷明文来测试<em>弱前向保密性</em>。在协议会话之前后的任何时候与${who[0].toUpperCase()}${who.substr(1)}的${longTermKeys[0]}一起，都能检索到明文。`,
				`在这个查询中，我们通过检查主动攻击者是否能够在协议会话之前只有通过破坏${whom[0].toUpperCase()}${whom.substr(1)}的${longTermKeys[1]}来检索有效载荷明文来测试<em>强前向保密性</em>。`,
			]
		};
		analysisTxt = [
			htmlTemplates.detailed.intro(pattern.name, abc, seq, dir),
		];
		analysisTxt = analysisTxt.concat(
			htmlTemplates.detailed.analysisTxt(pattern.name, abc, seq, dir, true, writeMessage, tokens)
		);
		analysisTxt = analysisTxt.concat(
			htmlTemplates.detailed.analysisTxt(pattern.name, abc, seq, dir, false, readMessage, tokens)
		);
		analysisTxt = analysisTxt.concat([
			`<h3>请求与结果</h3>`,
			`消息<span class="mono">${abc.toUpperCase()}</span>是针对4个认证查询和5个保密查询进行测试。`
		]);
		for (let i = 1; i < 5; i++) {
			analysisTxt = analysisTxt.concat([
				`<h4>身份认证等级 ${i}: ${(well(rawResultsActive[(message * 9) + i])) ? '<span class="passed">通过</span>' : '<span class="failed">失败</span>'}</h4>`,
				`<p class="proverif"><br />${rawResultsActive[(message * 9) + i]}</p>`,
				`<p>${queryExplanations.authentication[i]}</p>`
			]);
		}
		for (let i = 1; i < 6; i++) {
			let rawResults = ((i === 1) || (i === 3)) ? rawResultsPassive : rawResultsActive;
			let x = (i === 2) ? 1 : (i === 3) ? 2 : (i === 4) ? 2 : (i === 5) ? 3 : i
			analysisTxt = analysisTxt.concat([
				`<h4>保密等级 ${i}: ${(well(rawResults[((message * 9) + 5) + x])) ? '<span class="passed">通过</span>' : '<span class="failed">失败</span>'}</h4>`,
				`<p class="proverif"><br />${rawResults[((message * 9) + 5) + x]}</p>`,
				`<p>${queryExplanations.confidentiality[i]}</p>`
			]);
		}
		return {
			arrowSvg: arrowSvg.join('\n'),
			analysisTxt: analysisTxt.join('\n'),
			title: `${pattern.name} - 消息 ${abc.toUpperCase()}`
		}
	}

	if (typeof (module) !== 'undefined') {
		// Node
		module.exports = {
			read: read,
			render: render,
			renderDetailed: renderDetailed
		};
	} else {
		// Web
		NOISEREADER.read = read;
		NOISEREADER.render = render;
		NOISEREADER.renderDetailed = renderDetailed;
	}

})();
