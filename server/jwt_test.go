// Copyright 2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

const (
	uJWT = "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJRVzRWWktISEJCUkFaSkFWREg3UjVDSk1RQ1pHWDZJM1FJWEJSMkdWSjRHSVRMRlJRMlpBIiwiaWF0IjoxNTQyMzg1NjMxLCJpc3MiOiJBQ1E1VkpLS1dEM0s1QzdSVkFFMjJNT1hESkFNTEdFTUZJM1NDR1JWUlpKSlFUTU9QTjMzQlhVSyIsIm5hbWUiOiJkZXJlayIsInN1YiI6IlVEMkZMTEdGRVJRVlFRM1NCS09OTkcyUU1JTVRaUUtLTFRVM0FWRzVJM0VRRUZIQlBHUEUyWFFTIiwidHlwZSI6InVzZXIiLCJuYXRzIjp7InB1YiI6e30sInN1YiI6e319fQ.6PmFNn3x0AH3V05oemO28riP63+QTvk9g/Qtt6wBcXJqgW6YSVxk6An1MjvTn1tH7S9tJ0zOIGp7/OLjP1tbBQ"
	aJWT = "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJJSTdKSU5JUENVWTZEU1JDSUpZT1daR0k0UlRGNUdCNjVZUUtSNE9RVlBCQlpBNFhCQlhRIiwiaWF0IjoxNTQyMzMxNzgwLCJpc3MiOiJPRDJXMkk0TVZSQTVUR1pMWjJBRzZaSEdWTDNPVEtGV1FKRklYNFROQkVSMjNFNlA0NlMzNDVZWSIsIm5hbWUiOiJmb28iLCJzdWIiOiJBQ1E1VkpLS1dEM0s1QzdSVkFFMjJNT1hESkFNTEdFTUZJM1NDR1JWUlpKSlFUTU9QTjMzQlhVSyIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6e319.Dg2A1NCJWvXhBQZN9QNHAq1KqsFIKxzLhYvD5yH0DYZPC0gXtdhLkwJ5uiooki6YvzR8UNQZ9XuWgDpNpwryDg"
)

var (
	uSeed = []byte("SUAIO3FHUX5PNV2LQIIP7TZ3N4L7TX3W53MQGEIVYFIGA635OZCKEYHFLM")
	oSeed = []byte("SOAL7GTNI66CTVVNXBNQMG6V2HTDRWC3HGEP7D2OUTWNWSNYZDXWFOX4SU")
	aSeed = []byte("SAANRM6JVDEYZTR6DXCWUSDDJHGOHAFITXEQBSEZSY5JENTDVRZ6WNKTTY")
)

func opTrustBasicSetup() *Server {
	kp, _ := nkeys.FromSeed(oSeed)
	pub, _ := kp.PublicKey()
	opts := defaultServerOptions
	opts.TrustedNkeys = []string{string(pub)}
	s, _, _, _ := rawSetup(opts)
	return s
}

func buildMemAccResolver(s *Server) {
	s.mu.Lock()
	kp, _ := nkeys.FromSeed(aSeed)
	pub, _ := kp.PublicKey()
	mr := &memAccResolver{}
	mr.Store(string(pub), aJWT)
	s.accResolver = mr
	s.mu.Unlock()
}

func TestJWTUser(t *testing.T) {
	s := opTrustBasicSetup()
	// Check to make sure we would have an authTimer
	if !s.info.AuthRequired {
		t.Fatalf("Expect the server to require auth")
	}

	c, cr, _ := newClientForServer(s)

	// Don't send jwt field, should fail.
	go c.parse([]byte("CONNECT {\"verbose\":true,\"pedantic\":true}\r\nPING\r\n"))
	l, _ := cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR ") {
		t.Fatalf("Expected an error")
	}

	c, cr, _ = newClientForServer(s)

	// PING needed to flush the +OK/-ERR to us.
	// This should fail too since no account resolver is defined.
	cs := fmt.Sprintf("CONNECT {\"jwt\":%q,\"sig\":\"%s\",\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", uJWT, "xxx")
	go c.parse([]byte(cs))
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR ") {
		t.Fatalf("Expected an error")
	}

	// Ok now let's walk through and make sure all is good.
	// We will set the account resolver by hand to a memory resolver.
	buildMemAccResolver(s)

	c, cr, l = newClientForServer(s)

	// Sign Nonce
	kp, _ := nkeys.FromSeed(uSeed)

	var info nonceInfo
	json.Unmarshal([]byte(l[5:]), &info)
	sigraw, _ := kp.Sign([]byte(info.Nonce))
	sig := base64.StdEncoding.EncodeToString(sigraw)

	// PING needed to flush the +OK/-ERR to us.
	// This should fail too since no account resolver is defined.
	cs = fmt.Sprintf("CONNECT {\"jwt\":%q,\"sig\":\"%s\",\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", uJWT, sig)
	go c.parse([]byte(cs))
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "+OK") {
		t.Fatalf("Expected an OK, got: %v", l)
	}
}

func TestJWTUserBadTrusted(t *testing.T) {
	s := opTrustBasicSetup()
	// Check to make sure we would have an authTimer
	if !s.info.AuthRequired {
		t.Fatalf("Expect the server to require auth")
	}
	// Now place bad trusted key
	s.mu.Lock()
	s.trustedNkeys = []string{"bad"}
	s.mu.Unlock()

	buildMemAccResolver(s)

	c, cr, l := newClientForServer(s)

	// Sign Nonce
	kp, _ := nkeys.FromSeed(uSeed)

	var info nonceInfo
	json.Unmarshal([]byte(l[5:]), &info)
	sigraw, _ := kp.Sign([]byte(info.Nonce))
	sig := base64.StdEncoding.EncodeToString(sigraw)

	// PING needed to flush the +OK/-ERR to us.
	// This should fail too since no account resolver is defined.
	cs := fmt.Sprintf("CONNECT {\"jwt\":%q,\"sig\":\"%s\",\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", uJWT, sig)
	go c.parse([]byte(cs))
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR ") {
		t.Fatalf("Expected an error")
	}
}

func TestJWTUserExpired(t *testing.T) {
	// Create a new user that we will make sure has expired.
	nkp, _ := nkeys.CreateUser()
	pub, _ := nkp.PublicKey()
	nuc := jwt.NewUserClaims(string(pub))
	claims := nuc.Claims()
	claims.IssuedAt = time.Now().Add(-10 * time.Second).Unix()
	claims.Expires = time.Now().Add(-2 * time.Second).Unix()

	akp, _ := nkeys.FromSeed(aSeed)
	jwt, err := nuc.Encode(akp)
	if err != nil {
		t.Fatalf("Error generating user JWT: %v", err)
	}

	s := opTrustBasicSetup()
	buildMemAccResolver(s)

	c, cr, l := newClientForServer(s)

	// Sign Nonce
	var info nonceInfo
	json.Unmarshal([]byte(l[5:]), &info)
	sigraw, _ := nkp.Sign([]byte(info.Nonce))
	sig := base64.StdEncoding.EncodeToString(sigraw)

	// PING needed to flush the +OK/-ERR to us.
	// This should fail too since no account resolver is defined.
	cs := fmt.Sprintf("CONNECT {\"jwt\":%q,\"sig\":\"%s\",\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", jwt, sig)
	go c.parse([]byte(cs))
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR ") {
		t.Fatalf("Expected an error")
	}
}

func TestJWTUserPermissionClaims(t *testing.T) {
	nkp, _ := nkeys.CreateUser()
	pub, _ := nkp.PublicKey()
	nuc := jwt.NewUserClaims(string(pub))

	nuc.Permissions.Pub.Allow.Add("foo")
	nuc.Permissions.Pub.Allow.Add("bar")
	nuc.Permissions.Pub.Deny.Add("baz")
	nuc.Permissions.Sub.Allow.Add("foo")
	nuc.Permissions.Sub.Allow.Add("bar")
	nuc.Permissions.Sub.Deny.Add("baz")

	akp, _ := nkeys.FromSeed(aSeed)
	jwt, err := nuc.Encode(akp)
	if err != nil {
		t.Fatalf("Error generating user JWT: %v", err)
	}

	s := opTrustBasicSetup()
	buildMemAccResolver(s)

	c, cr, l := newClientForServer(s)

	// Sign Nonce
	var info nonceInfo
	json.Unmarshal([]byte(l[5:]), &info)
	sigraw, _ := nkp.Sign([]byte(info.Nonce))
	sig := base64.StdEncoding.EncodeToString(sigraw)

	// PING needed to flush the +OK/-ERR to us.
	// This should fail too since no account resolver is defined.
	cs := fmt.Sprintf("CONNECT {\"jwt\":%q,\"sig\":\"%s\",\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", jwt, sig)
	go c.parse([]byte(cs))
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "+OK") {
		t.Fatalf("Expected an OK, got: %v", l)
	}
	// Now check client to make sure permissions transferred.
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.perms == nil {
		t.Fatalf("Expected client permissions to be set")
	}

	if lpa := c.perms.pub.allow.Count(); lpa != 2 {
		t.Fatalf("Expected 2 publish allow subjects, got %d", lpa)
	}
	if lpd := c.perms.pub.deny.Count(); lpd != 1 {
		t.Fatalf("Expected 1 publish deny subjects, got %d", lpd)
	}
	if lsa := c.perms.sub.allow.Count(); lsa != 2 {
		t.Fatalf("Expected 2 subscribe allow subjects, got %d", lsa)
	}
	if lsd := c.perms.sub.deny.Count(); lsd != 1 {
		t.Fatalf("Expected 1 subscribe deny subjects, got %d", lsd)
	}
}
