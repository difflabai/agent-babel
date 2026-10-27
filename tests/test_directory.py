"""Synthetic directory labels never replace authenticated durable identities."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from babel.auth import Policy, ScopedStore
from babel.core import BridgeError, Store
from babel.directory import handle
from babel.enrollment import change, edit
from babel.mcp import dispatch
from babel.account_wake import fingerprint
from tests.test_participants import fixture, DOT, CODEX, SECOND, GUEST, GROK, TOKENS, wake
from tests.test_cloud import FakeTransport, KEY
from babel.events import EventService, EVENT_NAME

CID = 'directory-chat-01'


class DirectoryTests(unittest.TestCase):
    def setUp(self):
        self.cfg = fixture()
        self.cfg['participants'][DOT].update(display_name='Coordinator', role='Coordinator', aliases=['coord'])
        self.cfg['participants'][CODEX].update(display_name='Juniper', role='Build worker', aliases=['build'])
        self.cfg['participants'][GUEST].update(display_name='Juniper', role='Guest worker', aliases=['build'])
        self.cfg['conversations'][CID] = {'state':'active', 'participants':[DOT,CODEX,SECOND],
            'routes':[{'sender':DOT,'recipient':CODEX}, {'sender':CODEX,'recipient':DOT},
                      {'sender':DOT,'recipient':SECOND}, {'sender':SECOND,'recipient':DOT}]}
        self.store = Store(':memory:')
        self.reload()
        self.store.policy_provider = lambda: self.policy

    def tearDown(self):
        self.store.close()

    def reload(self):
        self.policy = Policy(copy.deepcopy(self.cfg))
        self.store.sync_policy(self.policy)

    def scope(self, role=DOT):
        return ScopedStore(self.store, role, self.policy.agents[role][1], self.policy)

    def send(self, recipient='build', role=DOT, **kwargs):
        return self.scope(role).stage(role, recipient, text='Selected text',
            message_id=kwargs.pop('message_id','directory-message-001'), **kwargs)

    def test_labels_platform_role_and_unconfigured_fallback(self):
        contacts = self.scope().contacts(DOT)
        c = next(c for c in contacts if c['recipient'] == CODEX)
        self.assertEqual((c['display_name'],c['platform'],c['role'],c['owner']),
                         ('Juniper','codex','Build worker','owner_a'))
        self.assertEqual(c['aliases'], ['build'])
        self.assertEqual(c['send_to'], handle(DOT,CODEX,CID))
        unknown = next(c for c in contacts if c['recipient'] == SECOND)
        self.assertFalse(unknown['name_configured'])
        self.assertEqual(unknown['display_name'], SECOND)
        self.assertNotIn(GROK, str(contacts))

    def test_unique_names_aliases_and_handles_resolve_before_persistence(self):
        for i, selector in enumerate(('JUNIPER', 'build', 'owner_a/build', handle(DOT,CODEX,CID))):
            row = self.send(selector, message_id='directory-send-'+str(i))['message']
            self.assertEqual((row['source'],row['recipient'],row['conversation_id']), (DOT,CODEX,CID))
            self.assertEqual(row['status'],'draft')
            self.assertIn('Juniper · codex · Build worker · owner_a',row['header'])
            self.assertEqual(row['recipient_contact']['id'], CODEX)
        raw = self.store.history()[0]
        self.assertNotIn('header', raw)
        self.assertNotIn('recipient_contact', raw)

    def test_canonical_ids_keep_legacy_contract_and_dedup(self):
        with self.assertRaises(BridgeError): self.send(CODEX)
        first = self.send(CODEX, conversation_id=CID)
        self.assertTrue(self.send()['duplicate'])
        self.assertFalse(first['duplicate'])
        self.assertEqual(len(self.store.history()),1)
        self.assertEqual(self.send(handle(DOT,CODEX,CID))['message']['id'], first['message']['id'])

    def test_cross_owner_names_require_explicit_namespace_or_handle(self):
        self.assertEqual(self.send('Juniper')['message']['recipient'], CODEX)
        other = self.send('owner_b/Juniper',message_id='cross-owner-message')['message']
        self.assertEqual((other['recipient'],other['conversation_id']), (GUEST,'chat_shared_01'))
        # Granted foreign names never become a fallback for a bare local name.
        self.cfg['participants'][CODEX]['aliases']=[]
        self.cfg['participants'][CODEX]['display_name']='Local worker'
        self.reload()
        with self.assertRaises(BridgeError): self.send('Juniper', message_id='foreign-fallback-01')
        with self.assertRaises(BridgeError): self.send('owner_b/unknown')
        foreign_handle=handle(DOT,GUEST,'chat_shared_01')
        with self.assertRaises(BridgeError): self.send(foreign_handle,role=SECOND)

    def test_duplicate_names_aliases_and_conversations_require_explicit_choice(self):
        self.cfg['participants'][SECOND].update(display_name='JUNIPER', aliases=['build'])
        self.reload()
        for selector in ('Juniper','build','owner_a/build'):
            with self.assertRaises(BridgeError) as exc: self.send(selector)
            self.assertEqual(exc.exception.status,409)
            self.assertIn('Ambiguous recipient',str(exc.exception))
            self.assertIn(handle(DOT,SECOND,CID),str(exc.exception))
            self.assertNotIn(GROK,str(exc.exception))
        self.assertEqual(self.send(handle(DOT,CODEX,CID))['message']['recipient'], CODEX)
        self.cfg['conversations']['directory-chat-02']=copy.deepcopy(self.cfg['conversations'][CID])
        self.reload()
        with self.assertRaises(BridgeError): self.send('build')
        with self.assertRaises(BridgeError): self.send(handle(DOT,CODEX,CID),conversation_id='directory-chat-02')
        self.assertEqual(self.send(handle(DOT,CODEX,CID))['message']['conversation_id'],CID)

    def test_handle_collision_fails_closed(self):
        with patch('babel.directory.handle',return_value='contact:collision'):
            with self.assertRaisesRegex(BridgeError,'Ambiguous'): self.send('contact:collision')

    def test_rename_preserves_handles_fingerprints_claims_and_receipts(self):
        row=self.send()['message']; self.store.approve(row['id'])
        recipient=self.scope(CODEX)
        claimed=recipient.claim_message(row['id'],CODEX,'directory-claim-001')
        self.assertTrue(claimed['claimed'])
        row=claimed["message"]
        before=self.policy.agents[CODEX][0]
        self.cfg['participants'][CODEX].update(display_name='Cedar',role='Reviewer',aliases=['review'])
        self.reload()
        self.assertEqual(self.policy.agents[CODEX][0],before)
        current=self.scope().message_status(row['id'],DOT)
        self.assertEqual(fingerprint(row),fingerprint(current))
        self.assertIn('Cedar · codex · Reviewer',current['header'])
        self.assertEqual(self.send(handle(DOT,CODEX,CID))['duplicate'],True)
        with self.assertRaises(BridgeError): self.send('build')
        ack=self.scope(CODEX).acknowledge(row['id'],CODEX,'directory-claim-001')
        self.assertEqual(ack['status'],'acknowledged')
        self.assertEqual(ack['recipient_contact']['display_name'],'Cedar')
        self.assertFalse(self.scope(CODEX).claim_message(row['id'],CODEX,'directory-claim-002')['claimed'])

    def test_reused_name_cannot_redirect_old_reply_or_message_retry(self):
        parent=self.send('coord',role=CODEX,message_id='reply-parent-0001')['message']
        self.store.approve(parent['id'])
        self.cfg['participants'][CODEX].update(display_name='Cedar',aliases=['review'])
        self.cfg['participants'][SECOND].update(display_name='Juniper',aliases=['build'])
        self.reload()
        with self.assertRaises(BridgeError): self.send('build',reply_to=parent['id'])
        reply=self.send(handle(DOT,CODEX,CID),reply_to=parent['id'])['message']
        self.assertEqual((reply['recipient'],reply['root_id'],reply['hops']),(CODEX,parent['id'],2))
        with self.assertRaises(BridgeError) as exc: self.send('build')
        self.assertEqual(exc.exception.status,409)
        self.assertEqual(self.store.message_status(reply['id'],DOT)['recipient'],CODEX)

    def test_inactive_and_ungranted_contacts_cannot_be_selected(self):
        old=handle(DOT,CODEX,CID)
        self.cfg['participants'][CODEX]['state']='closed'; self.reload()
        self.assertNotIn(CODEX,str(self.scope().contacts(DOT)))
        for selector in ('Juniper','build',old,CODEX):
            with self.assertRaises(BridgeError): self.send(selector,conversation_id=CID)
        self.cfg['participants'][GROK].update(display_name='Secret worker',aliases=['secret'])
        self.reload()
        for selector in ('owner_b/secret','owner_b/Secret worker',handle(DOT,GROK,'chat_private_01')):
            with self.assertRaises(BridgeError) as exc: self.send(selector)
            self.assertNotIn(GROK,str(exc.exception))

    def test_metadata_does_not_change_authorization_or_wake_subscription(self):
        service=EventService(self.store,self.policy,wake(),FakeTransport())
        service.subscribe(GUEST,{'name':EVENT_NAME,'arguments':{'recipient':GUEST},
            'delivery':{'mode':'webhook','url':'https://guest.example.com/callback','secret':KEY}})
        before=self.policy.agents[GUEST][0]
        self.cfg['participants'][GUEST].update(display_name='Cedar',aliases=['cedar'],role='Review')
        self.reload()
        self.assertEqual(before,self.policy.agents[GUEST][0])
        self.assertEqual(self.store.wake_status()['active_subscriptions'],1)
        self.assertEqual(self.policy.authenticate('Bearer '+TOKENS[GUEST]),GUEST)
        self.cfg['conversations']['chat_shared_01']['routes']=[]; self.reload()
        self.assertEqual(self.store.wake_status()['active_subscriptions'],0)
        with self.assertRaises(BridgeError): self.send('owner_b/Cedar')

    def test_all_tool_message_surfaces_include_readable_headers(self):
        row=self.send()['message']; self.store.approve(row['id'])
        def call(role,name,**args):
            rpc={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}}
            result=dispatch(self.scope(role),role,rpc)['result']
            self.assertFalse(result['isError'],result)
            return json.loads(result['content'][0]['text'])
        for name in ('receive_messages','bridge_history'):
            self.assertIn('Juniper',call(CODEX,name)['messages'][0]['header'])
        self.assertIn('Juniper',call(DOT,'message_status',message_id=row['id'])['message']['header'])
        self.assertIn('Juniper',call(CODEX,'claim_message',message_id=row['id'],claim_id='tool-claim-0001')['message']['header'])
        self.assertIn('Juniper',call(CODEX,'acknowledge_message',message_id=row['id'],claim_id='tool-claim-0001')['message']['header'])

    def test_legacy_scoped_callers_keep_canonical_routes(self):
        cfg={'schema_version':1,'agents':{'ada':{'sha256':'1'*64,'recipients':['grokbot']},
             'grokbot':{'sha256':'2'*64,'recipients':['ada']}}}
        policy=Policy(cfg); scope=ScopedStore(self.store,'ada',policy.agents['ada'][1],policy)
        contacts=scope.contacts('ada');self.assertEqual(contacts[0]['recipient'],'grokbot')
        row=scope.stage('ada','grokbot',text='Legacy',message_id='legacy-directory-001')['message']
        self.assertIsNone(row['conversation_id']); self.assertEqual(row['source'],'ada')
        self.assertTrue(scope.stage('ada',contacts[0]['send_to'],text='Legacy',message_id=row['id'])['duplicate'])

    def test_metadata_validation_and_host_only_label_edit(self):
        for field,value in (('display_name',CODEX),('display_name','contact:123'),
                            ('display_name','Bad\nName'),('display_name','\u202eevil'),('display_name','line\u2028break'),('role',' x'),
                            ('aliases',['contact:bad']),('aliases',['Not normalized']),('aliases',['x','x']),
                            ('aliases','worker'),('display_name',''),('role',42)):
            cfg=copy.deepcopy(self.cfg);cfg['participants'][CODEX][field]=value
            with self.subTest(field=field,value=value), self.assertRaises(BridgeError): Policy(cfg)
        updated=change(self.cfg,'label',participant=CODEX,display_name='Cedar',role='Reviewer',aliases=['cedar'])
        self.assertEqual(Policy(updated).agents,self.policy.agents)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'policy.json';path.write_text(json.dumps(self.cfg));path.chmod(0o600)
            edit(path,'label',participant=CODEX,display_name='Cedar')
            self.assertEqual(json.loads(path.read_text())['participants'][CODEX]['display_name'],'Cedar')
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_confirmed_mapping_batch_preserves_authority_and_supports_ada(self):
        from babel.core import ROOT
        metadata=json.loads((ROOT/'deploy/directory.bits255.json').read_text())
        cfg=fixture(); source='bits255.claude.duet_20261025'; target='bits255.grokbot.grok_20261002'
        cfg['owners']={'bits255':{'enabled':True}}; cfg['participants']={}; cfg['conversations']={}
        for i,pid in enumerate(metadata):
            owner,client,session=pid.split('.')
            entry=copy.deepcopy(fixture()['participants'][CODEX])
            entry.update(owner=owner,client=client,session=session,sha256=str(i+1)*64)
            cfg['participants'][pid]=entry
        cfg['conversations'][CID]={'state':'active','participants':[source,target],
            'routes':[{'sender':source,'recipient':target}]}
        before=Policy(cfg)
        after=change(cfg,'directory',metadata=metadata); policy=Policy(after)
        self.assertEqual(before.agents,policy.agents)
        scope=ScopedStore(self.store,source,policy.agents[source][1],policy)
        row=scope.stage(source,'ada',text='Selected',message_id='confirmed-name-001')['message']
        self.assertEqual(row['recipient'],target)
        self.assertIn('Claude · Anthropic',row['header']); self.assertIn('Ada · Grok',row['header'])
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'policy.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
            edit(path,'directory',metadata_file=str(ROOT/'deploy/directory.bits255.json'))
            self.assertEqual(json.loads(path.read_text()),after)
            saved=path.read_bytes()
            bad=Path(folder)/'bad.json';bad.write_text(json.dumps({source:{'sha256':'9'*64}}))
            with self.assertRaises(BridgeError): edit(path,'directory',metadata_file=str(bad))
            self.assertEqual(path.read_bytes(),saved)
        with self.assertRaises(BridgeError): change(self.cfg,'directory',metadata=metadata)
        with self.assertRaises(BridgeError): change(cfg,'directory',metadata={source:{'owner':'owner_b'}})

    def test_authenticated_mcp1_and_mcp2_short_route_round_trips(self):
        import threading
        from urllib.request import Request, ProxyHandler, build_opener
        from babel.gateway import Gateway
        from babel import mcp2
        server=Gateway(0,self.policy,'https://bridge.example.com',self.store,transport=FakeTransport())
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        opener=build_opener(ProxyHandler({}))
        def call(modern,role,name,**args):
            params={'name':name,'arguments':args}
            headers={'Host':'bridge.example.com','X-Forwarded-Proto':'https',
                'Authorization':'Bearer '+TOKENS[role], 'Content-Type':'application/json',
                'Accept':'application/json, text/event-stream'}
            if modern:
                params['_meta']={mcp2.PREFIX+'protocolVersion':mcp2.VERSION,
                                 mcp2.PREFIX+'clientCapabilities':{}}
                headers.update({'MCP-Protocol-Version':mcp2.VERSION,'Mcp-Method':'tools/call','Mcp-Name':name})
            body={'jsonrpc':'2.0','id':1,'method':'tools/call','params':params}
            req=Request('http://127.0.0.1:'+str(server.port)+('/mcp' if modern else '/mcp/v1'),
                        data=json.dumps(body).encode(),headers=headers)
            with opener.open(req,timeout=3) as response: result=json.load(response)['result']
            self.assertFalse(result.get('isError'),result)
            return json.loads(result['content'][0]['text'])
        try:
            for modern in (False,True):
                contacts=call(modern,DOT,'list_contacts')['contacts']
                contact=next(c for c in contacts if c['recipient']==CODEX)
                row=call(modern,DOT,'stage_message',recipient=contact['send_to'],text='Selected',
                         message_id='transport-directory-'+str(modern))['message']
                self.assertEqual(row['recipient'],CODEX);self.assertIn('Juniper',row['header'])
                self.store.approve(row['id'])
                incoming=call(modern,CODEX,'receive_messages')['messages']
                self.assertEqual([r['id'] for r in incoming],[row['id']])
                claim='transport-claim-'+str(modern)
                self.assertTrue(call(modern,CODEX,'claim_message',message_id=row['id'],claim_id=claim)['claimed'])
                call(modern,CODEX,'acknowledge_message',message_id=row['id'],claim_id=claim)
                answer=call(modern,CODEX,'stage_message',recipient='coord',text='Answer',
                            message_id='transport-reply-'+str(modern),reply_to=row['id'])['message']
                self.assertEqual((answer['recipient'],answer['conversation_id'],answer['root_id']), (DOT,CID,row['id']))
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_operator_collision_labels_are_distinct_and_retired_names_stay_distinct(self):
        from babel.directory import operator_labels
        self.cfg['participants'][SECOND].update(display_name='Juniper',role='Build worker',aliases=['build'])
        self.reload()
        labels=operator_labels(self.policy,self.policy.participants)
        self.assertNotEqual(labels[CODEX],labels[SECOND])
        self.assertIn('Juniper · codex · Build worker · owner_a [#',labels[CODEX])
        self.assertLess(len(labels[CODEX].split('[#')[1].rstrip(']')),len(CODEX))
        self.assertNotIn(CODEX,labels[CODEX])
        self.cfg['participants'][SECOND]['state']='closed';self.reload()
        retired=operator_labels(self.policy,self.policy.participants)
        self.assertEqual(retired[CODEX],labels[CODEX]);self.assertEqual(retired[SECOND],labels[SECOND])
        with patch('babel.directory.hashlib.sha256') as sha:
            sha.return_value.hexdigest.return_value='a'*64
            fallback=operator_labels(self.policy,self.policy.participants)
        self.assertEqual(fallback[CODEX],CODEX);self.assertEqual(fallback[SECOND],SECOND)

    def test_private_operator_session_disambiguates_canonical_compose_and_approval_targets(self):
        import threading
        from urllib.request import Request, ProxyHandler, build_opener
        from babel.server import Server
        self.cfg['participants'][SECOND].update(display_name='Juniper',role='Build worker',aliases=['build'])
        self.reload()
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'policy.json';path.write_text(json.dumps(self.cfg))
            with patch.dict('os.environ',{'BABEL_AUTH_FILE':str(path)}): server=Server(0,self.store)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            opener=build_opener(ProxyHandler({}));base='http://127.0.0.1:'+str(server.port)
            def call(route,body=None,csrf=None):
                headers={'Content-Type':'application/json'}
                if csrf: headers['X-Babel-CSRF']=csrf
                request=Request(base+route,data=None if body is None else json.dumps(body).encode(),headers=headers)
                with opener.open(request,timeout=3) as response:return json.load(response)
            try:
                session=call('/api/session')
                self.assertNotEqual(session['directory'][CODEX],session['directory'][SECOND])
                self.assertIn(CODEX,session['agents']);self.assertIn(SECOND,session['agents'])
                for index,recipient in enumerate((CODEX,SECOND)):
                    row=call('/api/stage',{'source':DOT,'recipient':recipient,'text':'Same selected content',
                        'conversation_id':CID,'message_id':'operator-collision-'+str(index)},session['csrf'])['message']
                    self.assertEqual(row['recipient'],recipient);self.assertEqual(row['status'],'draft')
                rows=call('/api/history')['messages'];self.assertEqual({r['recipient'] for r in rows},{CODEX,SECOND})
                self.cfg['participants'][SECOND]['state']='closed';path.write_text(json.dumps(self.cfg))
                session=call('/api/session')
                self.assertNotIn(SECOND,session['agents'])
                self.assertNotEqual(session['directory'][CODEX],session['directory'][SECOND])
            finally:
                server.shutdown();server.server_close();thread.join()
