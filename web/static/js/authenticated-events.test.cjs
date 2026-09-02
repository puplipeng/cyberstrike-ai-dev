const test = require('node:test');
const assert = require('node:assert/strict');
const {createSSEParser,openAuthenticatedEventStream} = require('./authenticated-events.js');

test('SSE parser handles split CRLF, comments, and multiline events', () => {
    const out=[]; const push=createSSEParser(e=>out.push(e.data));
    push(': keepalive\r');push('\ndata: one\r\ndata: two\r');push('\n\r\n');
    push('event: other\ndata: ignored\n\ndata: three\n\n');
    assert.deepEqual(out,['one\ntwo','three']);
});
test('SSE buffers are bounded', () => {
    assert.throws(()=>createSSEParser(()=>{})('x'.repeat(1024*1024+1)),/too large/);
    assert.throws(()=>createSSEParser(()=>{})('data: '+'x'.repeat(1024*1024+1)+'\n'),/too large/);
});
test('authenticated event stream uses fetch and stops after close', async () => {
    let signal,streamController; const messages=[]; const calls=[];
    const stream=openAuthenticatedEventStream('/api/c2/events/stream',{
        fetch:async(url,options)=>{
            calls.push(url); signal=options.signal;
            assert.equal(options.headers.Accept,'text/event-stream');
            return new Response(new ReadableStream({start(c){streamController=c;}}),{headers:{'Content-Type':'text/event-stream'}});
        },onmessage:e=>messages.push(e.data)
    });
    await new Promise(resolve=>setImmediate(resolve));
    streamController.enqueue(new TextEncoder().encode('data: {"ok":true}\n\n'));
    await new Promise(resolve=>setImmediate(resolve));
    stream.close();
    assert.equal(signal.aborted,true);
    streamController.close();
    await new Promise(resolve=>setImmediate(resolve));
    assert.deepEqual(messages,['{"ok":true}']);
    assert.deepEqual(calls,['/api/c2/events/stream']);
});
test('authentication errors cancel the body and do not schedule reconnect', async () => {
    let canceled=false,calls=0;
    const stream=openAuthenticatedEventStream('/api/c2/events/stream',{fetch:async()=>{
        calls++;
        return new Response(new ReadableStream({cancel(){canceled=true;}}),{status:401});
    }});
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(canceled,true);assert.equal(calls,1);stream.close();
});
