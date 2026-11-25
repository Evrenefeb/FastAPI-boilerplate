"""Proposed Phase B requirements: functional oracles, not OpenAPI parity."""
REQUIREMENTS = {
    'FR01': 'A visitor can create a usable ordinary account; duplicate usernames cannot create another account and duplicate email does not disclose account existence.',
    'FR02': 'Registration accepts documented boundary values and rejects invalid data or privilege injection without persisting an account.',
    'FR03': 'Correct username/email and password authenticate the intended account; incorrect credentials grant no session.',
    'FR04': 'Sessions identify the caller and cease granting access after logout, logout-all, inactivity or account deactivation.',
    'FR05': 'Signed-in users can retrieve their own private profile and another active user’s public profile; missing users are reported.',
    'FR06': 'A user can update permitted own-profile fields; changes persist, omitted fields stay unchanged, and rejected updates are atomic.',
    'FR07': 'Anonymous or insufficiently privileged callers cannot perform protected actions; granted/revoked permissions take effect for real sessions.',
    'FR08': 'Session-authenticated mutations require the matching CSRF token; missing, wrong or another session’s token must not change state.',
    'FR09': 'Own-account deactivation persists, removes public visibility and prevents both new login and existing-session use.',
}
CASES=[]
def add(id, req, technique, scenario, inputs, steps, expected, pre='Fresh disposable PostgreSQL tables; no production data; CSRF enabled; real API-created accounts and cookie sessions as specified.'):
    CASES.append(dict(id=id, requirement=req, functional_requirement=REQUIREMENTS[req], technique=technique,
        scenario=scenario, preconditions=pre, input=inputs, steps=steps, expected=expected, sequence=len(CASES)+1))

add('B01','FR01','Positive; end-to-end state transition','registration',{},
    'Register an account, independently read its committed row, log in, retrieve own profile.',
    '201 fixed confirmation; exactly one ordinary active account; usable credentials; 200 own profile matches persisted identity.')
add('B02','FR01','Negative; equivalence partition','duplicate_username',{},
    'Register account A, retry same username with another email, compare all stored user state.',
    '409 conflict; no new account and original account unchanged.')
add('B03','FR01','Negative; duplicate identity / privacy','duplicate_email',{},
    'Register account A, retry same email with a different username, compare response and stored state; capture outbound notice locally.',
    'Same 201 confirmation; no second account; existing account unchanged; notice handed to local email sink, not externally delivered.')
add('B04','FR02','Boundary-value analysis: minimum accepted','registration',{'name':'Ab','username':'ab','password':'Aa1!bcde'},
    'Register using 2-character name/username and 8-character policy-compliant password, then log in.',
    '201; exact values persisted and credentials work.')
add('B05','FR02','Boundary-value analysis: maximum accepted','registration',{'name':'N'*30,'username':'u'*32},
    'Register a 30-character name and 32-character username, then log in.',
    '201; full untruncated values persisted and credentials work.')
INVALID = {
    'missing': {'omit':'username'}, 'email': {'email':'not-an-email'}, 'uppercase': {'username':'UpperCase'},
    'name-short': {'name':'A'}, 'name-long': {'name':'N'*31}, 'username-short': {'username':'u'},
    'username-long': {'username':'u'*33}, 'password-short': {'password':'Aa1!bcd'},
    'password-class': {'password':'lowercase1!'}, 'privilege': {'is_superuser':True},
}
for label, values in INVALID.items():
    add('B06-'+label,'FR02','Boundary-value analysis' if any(x in label for x in ('short','long')) else 'Negative; equivalence partition',
        'invalid_registration',values,'Submit the indicated invalid signup and compare committed user state before/after.',
        '422; no account created; no session cookie or credential echo.')
for id, scenario, value in [('B07','bad_login','wrong password for existing username'),('B08','unknown_login','unknown username'),('B09','email_login','registered email in username form field')]:
    add(id,'FR03','Positive' if id=='B09' else 'Negative; equivalence partition',scenario,{'credential':value},
        'Create an account; submit the selected login credentials; request /users/me and compare committed account state.',
        '200 with correct identity and working real session; account unchanged.' if id=='B09' else '401 login; no session; /users/me remains 401; account unchanged.')
for method in ('GET','PATCH','DELETE'):
    add('B10-'+method,'FR07','Unauthorized access', 'anonymous',{'method':method},
        'Create an account without login; call protected read/update/deactivate route and compare committed state.',
        '401; no user data disclosed and account state unchanged.')
add('B11','FR05','Positive and negative lookup partitions','profile',{},
    'Log in as A, read own profile, read B’s profile, then read an absent username.',
    'Own identity/email correct; B exposes only public display fields matching database; absent username returns 404.')
add('B12','FR06','Positive; durable state transition','update',{},
    'Log in as A, PATCH name/avatar with CSRF; read committed rows; use an independent new login to read changes.',
    '200; exact requested changes survive new session; unchanged identity/password/email and other account unaffected.')
add('B13','FR06','Negative; conflict and atomicity','rename_conflict',{},
    'A attempts to rename itself to B’s username while also changing name, using valid CSRF; compare all stored rows.',
    '409; no partial name/username change and no other account change.')
for label,values in [('null',{'name':None}),('email',{'email':'replacement@example.com'}),('avatar',{'profile_image_url':'not-a-url'})]:
    add('B14-'+label,'FR06','Negative; invalid update with persistence oracle','invalid_update',values,
        'Log in, send indicated PATCH with valid CSRF, compare full committed user state.',
        '422; existing profile remains unchanged. This checks atomic behavior, not D2 schema parity.')
for action in ('patch-other','delete-other','anonymize-other','admin-read'):
    add('B15-'+action,'FR07','Unauthorized access; ownership/role decision table','forbidden',{'action':action},
        'Create A/B; log in as ordinary A; attempt indicated protected operation on B with valid CSRF; compare DB state.',
        '403; B’s data not returned or changed and A unchanged.')
for method in ('PATCH','DELETE','LOGOUT'):
    for token in ('missing','wrong','foreign'):
        add('B16-'+method+'-'+token,'FR08','Decision table: action × CSRF credential','csrf',{'action':method,'token':token},
            'Log in as A; obtain a separate B session for foreign-token case; send mutation with selected CSRF header; compare DB; retry protected GET using A’s cookie.',
            '403; no database mutation; A’s session remains usable. Missing-header case retains the CSRF cookie to prove cookie alone is insufficient.')
add('B17','FR04','State transition; logout and replay','logout',{},
    'Log in; save cookie; POST logout with CSRF; check cookie clearing; replay old cookie from another client.',
    '200 logout; client session cookie removed; both client and old-cookie replay get 401; user account remains active.')
add('B18','FR04','State transition; multi-session invalidation','logout_all',{},
    'Log in twice independently; confirm both identities; logout-all from one session; replay both saved cookies.',
    '200; exactly two sessions revoked; both previously valid cookies get 401; account remains active.')
add('B19','FR07','Positive/negative transition; permission grant and revoke','role_lifecycle',{},
    'Seed a test-only admin flag on an API-created account, then log in normally. Ordinary user gets 403; admin creates reader role, assigns it, then removes it; repeat listing with same user session.',
    '403 → 200 → 403 in the same ordinary session; role and assignment persist on grant and assignment is gone after revocation. No authentication override.')
add('B20','FR04','Temporal boundary; actual idle wait','expiration',{'idle_timeout_minutes':1,'wait_seconds':62},
    'Log in; GET own profile successfully; send no requests for 62 seconds using real elapsed time; replay same cookie.',
    'Session usable before timeout and 401 after inactivity; account unchanged. This tests configured 1-minute idle timeout, not default 30-minute duration.')
add('B21','FR09','State transition; deactivation across sessions','deactivation',{},
    'Create A/B; log A in twice and B once; deactivate A with real CSRF; check fresh DB row, both A cookies, fresh A login and B’s lookup of A.',
    '200; retained row marked deleted with timestamp; both A sessions and new login get 401; B sees 404 for A; B remains active.')
add('B22','FR07','Negative; privilege restriction','role_denied',{},
    'Log in as ordinary user; attempt to create a role granting user.read; compare role table and user state.',
    '403; no role created and account remains ordinary/unchanged.')
add('B23','FR06','Boundary: empty partial update','empty_update',{},
    'Log in; PATCH an empty object with valid CSRF; compare user business fields and read own profile.',
    '200; no business field changes (updated_at may change); profile remains accessible.')
