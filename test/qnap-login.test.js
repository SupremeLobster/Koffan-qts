const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../static/qnap-login.js'), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

function browser({ app='https://shopping.example', next='/lists/42', statuses=[], logins=[] }={}) {
    const status={textContent:'Use your QTS account'};
    const password={value:'private password'};
    const code={value:'',required:false,focus(){this.focused=true;}};
    const button={disabled:false,textContent:'Sign in'};
    const attributes={};
    const handlers={},timers=new Map(),requests=[],navigations=[];
    let now=0,id=0;
    const form={
        addEventListener:(event,fn)=>{handlers['form:'+event]=fn;},
        reportValidity:()=>true,
        setAttribute:(key,value)=>{attributes[key]=value;},
        removeAttribute:key=>{delete attributes[key];}
    };
    const elements={'status':status,'qts-login-form':form,'qts-password':password,'qts-code':code,'qts-submit':button};
    const document={
        body:{dataset:{next}},hidden:false,
        getElementById:id=>elements[id],
        addEventListener:(event,fn)=>{handlers[event]=fn;}
    };
    const origin=new URL(app);
    const window={
        location:{origin:origin.origin,hostname:origin.hostname,protocol:origin.protocol,replace:url=>navigations.push(url)},
        addEventListener:(event,fn)=>{handlers[event]=fn;}
    };
    class FormData {
        constructor(){this.values=[['username','alice'],['password',password.value],['security_code',code.value],['csrf','nonce'],['next',next]];}
        [Symbol.iterator](){return this.values[Symbol.iterator]();}
    }
    vm.runInNewContext(source,{
        URL,URLSearchParams,FormData,AbortController,document,window,
        Date:{now:()=>now},
        setTimeout:(fn,delay)=>{timers.set(++id,{fn,delay});return id;},
        clearTimeout:id=>timers.delete(id),
        fetch:async(url,options)=>{
            requests.push({url,options});
            const queue=url==='/auth/qts/login'?logins:statuses;
            let reply=queue.shift() || {status:401,body:{authenticated:false}};
            if(typeof reply==='function') reply=await reply();
            if(reply instanceof Error) throw reply;
            return {status:reply.status,ok:reply.status>=200&&reply.status<300,json:async()=>reply.body};
        }
    });
    return {
        status,password,code,button,handlers,timers,requests,navigations,attributes,
        submit:()=>handlers['form:submit']({preventDefault(){}}),
        advance:delta=>{now+=delta;},
        poll:async()=>{
            const entry=[...timers].find(([,timer])=>timer.delay===3000);
            assert.ok(entry,'session polling is scheduled');
            timers.delete(entry[0]);await entry[1].fn();
        }
    };
}

test('existing QTS session opens the requested list without entering credentials',async()=>{
    const b=browser({statuses:[{status:200,body:{authenticated:true}}]});
    await settle();
    assert.deepEqual(b.navigations,['https://shopping.example/lists/42']);
    assert.equal(b.requests[0].options.cache,'no-store');
    assert.equal(b.requests[0].options.credentials,'same-origin');
    assert.equal(b.timers.size,0);
});

test('native login sends credentials only in a POST body and clears fields on success',async()=>{
    const b=browser({logins:[{status:200,body:{authenticated:true,redirect:'/lists/42'}}]});
    await settle();
    await b.submit();
    const request=b.requests.find(r=>r.url==='/auth/qts/login');
    assert.equal(request.options.method,'POST');
    assert.equal(request.options.body.get('password'),'private password');
    assert.equal(request.options.body.get('csrf'),'nonce');
    assert.equal(request.options.redirect,'error');
    assert.equal(b.password.value,'');
    assert.equal(b.code.value,'');
    assert.deepEqual(b.navigations,['https://shopping.example/lists/42']);
});

test('MFA challenge asks for a security code and resubmits without storing the password',async()=>{
    const b=browser({logins:[
        {status:401,body:{error:'security_code_required',message:'Enter your security code'}},
        {status:200,body:{authenticated:true,redirect:'/'}}
    ]});
    await settle();await b.submit();
    assert.equal(b.code.required,true);
    assert.equal(b.code.focused,true);
    assert.equal(b.password.value,'private password');
    assert.equal(b.navigations.length,0);
    b.code.value='123456';await b.submit();
    const posts=b.requests.filter(r=>r.url==='/auth/qts/login');
    assert.equal(posts[1].options.body.get('security_code'),'123456');
    assert.equal(b.password.value,'');
    assert.equal(b.navigations.length,1);
});

test('invalid credentials, rate limits and outages stay on the form and enable retry',async()=>{
    for(const reply of [
        {status:401,body:{error:'invalid_credentials',message:'Incorrect credentials'}},
        {status:429,body:{error:'rate_limited',message:'Try later'}},
        {status:503,body:{error:'qts_unavailable',message:'Unavailable'}},
        new Error('offline')
    ]){
        const b=browser({logins:[reply]});await settle();await b.submit();
        assert.equal(b.navigations.length,0);
        assert.equal(b.button.disabled,false);
        assert.equal(b.attributes['aria-busy'],undefined);
        assert.ok(b.status.textContent.length>0);
    }
});

test('native login works on its own hostname but rejects insecure or external destinations',async()=>{
    const b=browser({app:'https://shopping2.mafucat.com'});await settle();
    assert.equal(b.button.disabled,false);
    for(const options of [{app:'http://shopping2.mafucat.com'},{next:'//evil.example/'}]){
        const rejected=browser(options);
        assert.equal(rejected.button.disabled,true);
        assert.equal(rejected.requests.length,0);
    }
});

test('an external redirect in an unexpected API response is rejected',async()=>{
    const b=browser({logins:[{status:200,body:{authenticated:true,redirect:'https://evil.example/'}}]});
    await settle();await b.submit();
    assert.equal(b.navigations.length,0);
    assert.equal(b.button.disabled,false);
});

test('duplicate submissions do not create duplicate NAS sign-ins',async()=>{
    let finish;
    const b=browser({logins:[()=>new Promise(resolve=>{finish=resolve;})]});
    await settle();const pending=b.submit();await b.submit();
    assert.equal(b.requests.filter(r=>r.url==='/auth/qts/login').length,1);
    finish({status:200,body:{authenticated:true,redirect:'/'}});await pending;
    assert.equal(b.navigations.length,1);
});

test('background session polling cannot interrupt an in-progress credential submission',async()=>{
    let finish;
    const b=browser({logins:[()=>new Promise(resolve=>{finish=resolve;})]});
    await settle();const pending=b.submit();const count=b.requests.length;
    await b.handlers.focus();assert.equal(b.requests.length,count);
    finish({status:401,body:{error:'invalid_credentials',message:'Incorrect'}});await pending;
    await b.poll();assert.equal(b.status.textContent,'Incorrect');
});

test('returning from another QTS tab checks for an existing session immediately',async()=>{
    const b=browser({statuses:[{status:401,body:{}},{status:200,body:{authenticated:true}}]});
    await settle();await b.handlers.focus();
    assert.equal(b.navigations.length,1);
});

test('background polling stops after navigation or fifteen minutes',async()=>{
    const b=browser();await settle();b.advance(15*60*1000);await b.poll();
    assert.equal(b.timers.size,0);
    const other=browser();await settle();other.handlers.pagehide();
    assert.equal(other.timers.size,0);
});

test('switching usernames clears the previous account MFA requirement',async()=>{
    const b=browser({logins:[{status:401,body:{error:'security_code_required',message:'Enter code'}}]});
    await settle();await b.submit();
    assert.equal(b.code.required,true);
    b.code.value='123456';
    b.handlers['form:input']({target:{name:'username'}});
    assert.equal(b.code.required,false);
    assert.equal(b.code.value,'');
});
