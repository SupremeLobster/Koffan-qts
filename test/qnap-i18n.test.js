const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(require.resolve('../static/qnap-i18n.js'), 'utf8');
const locales = {};
for (const file of fs.readdirSync(path.join(__dirname,'../i18n')).filter(file=>file.endsWith('.json'))) {
    const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'../i18n',file),'utf8'));
    locales[raw.meta.code]={...raw.qts,retry_logout:raw.offline.retry,logout_title:raw.nav.logout};
}
function browser({stored='ca',server='en',disabled=false}={}) {
    const text={dataset:{qtsText:'account_managed'}},frame={dataset:{qtsTitle:'login_title'}};
    const document={
        cookie:'',documentElement:{},body:{dataset:{qtsPageTitle:'login_title'}},
        getElementById:()=>({textContent:JSON.stringify({lang:server,locales})}),
        querySelectorAll:selector=>selector==='[data-qts-text]'?[text]:[frame]
    };
    const window={};
    vm.runInNewContext(source,{
        window,document,location:{protocol:'https:'},
        localStorage:{getItem:()=>{if(disabled)throw new Error('disabled');return stored;}}
    });
    return {window,document,text,frame};
}

test('saved Catalan choice applies after logout has removed the language cookie',()=>{
    const b=browser();
    assert.equal(b.document.documentElement.lang,'ca');
    assert.equal(b.document.title,'Inicia la sessió amb QTS · Koffan');
    assert.equal(b.frame.title,'Inicia la sessió amb QTS');
    assert.equal(b.text.textContent,'El compte i la contrasenya es gestionen a QTS.');
    assert.match(b.document.cookie,/lang=ca;/);
    assert.match(b.window.qnapTranslate('logout_expired'),/ha caducat/);
});

test('unsupported or inaccessible saved language falls back to the server language',()=>{
    for(const options of [{stored:'unsupported',server:'es'},{disabled:true,server:'es'}]){
        const b=browser(options);
        assert.equal(b.document.documentElement.lang,'es');
        assert.equal(b.document.title,'Inicia sesión con QTS · Koffan');
    }
});

test('every supported saved language is available without an extra network request',()=>{
    for(const code of Object.keys(locales)){
        const b=browser({stored:code});
        assert.equal(b.document.documentElement.lang,code);
        assert.equal(b.window.qnapTranslate('account_managed'),locales[code].account_managed);
    }
});
