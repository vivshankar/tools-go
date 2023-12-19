package jwt

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJWTSigning(t *testing.T) {
	type testCase struct {
		desc           string
		privateKey     []byte
		payload        interface{}
		headers        map[string]interface{}
		expectedError  error
		expectedResult string
	}

	testCases := []testCase{
		{
			desc:       "RSA PEM signer",
			privateKey: []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAnyEEwueLcSFRUSPdy9AL5Vf6X7QDuL8mFMOR2liM1LeluSHC\nSYIoN+h6xxMkwDfr6626EOhJVxMxeBuLaG+/3QWWjvicUdIpevj73U1jqQT7MaMP\nI3ms7rm0v1OHfabyLbrCjDniL/8Ym15H/RwVqF31kXIcKVqMtJWRWkeoOrSSqUq4\nh28rRDUi8HXUTAvSoQYnZ+J+sICME7G+ZYVJtIQObT6AjMuM/y54vCH8ViVE9aOQ\n2rV3Wi+TKEgiV9Ik1KB6EdzCB4CYK2HYy/OgheF0ggeWuwHOegBpVR4BqlQyZJKJ\nyhKhWZhfYHmWkm/V+7KZtrWHoVQ/NhOAcT18qwIDAQABAoIBAQCTmvYmsM8IvmYG\nhOV849vU/jmxwnJdUXnKcup9BfyEaGFiC+2DcCdMTOpudNR3NKgzMi/Q9RbqnVQa\n3DoBQv9OzpssvXGK+A4gEorWaa3TH1q+XUlyl7AQtNPzUVDx/gTQ5FcH6b1k1hSG\nMftGzmFMjvN12cpDlcnEzKRKgQOMh3Kb5qm2ZSHRjxRzNBqRJOSOinJmpA+7a+Xg\nExfGle+P2lNoFFv/Abu852Jt0aUCc1FmiwRHmjtorSj9tHBJ4YQBCz7kD0C8kW3W\n3AwkwQCjDOKHyv99qzQ5cnV1uz9Bl/HfnConwyrA4iZcuegPGM53ZYBVzWHAKORW\nlZSOSLVpAoGBAM9TJJb7WvysNau/TzISu5xxlTCE6MsfWDyoxAkAgGg6NNsQmQjg\nc/k57+jU8MLHaBylOAo0n+03Q+/86U2onsiJD0Vz5zJUgjLetunw+fBJyMLyibUw\nsMx8/HW7e5R+ooauMQ+DTWxNsVIj+h4yhlslDOkbjUUqX1z2xAJm7JaVAoGBAMR9\nKO7ete5uBHOZQ9oDHBQx/1bjSPqdkbwwBetKTgPjUa8iYcKiZG0wgHlAHmsm4dQr\n93Ad03ZftdDqa4kua5etr5oVWVMGlIRrLY8E1FAU00ZJe7yBMB1r1l7XKR2sWz9g\n1ddTiYU6AJ3W3FbwKDgpmCkbWrG5pVZXrTPU/TY/AoGBAIcKEbgh6mbPyHmgt3XX\nC8pflRwwRe0f8no4Ns/iOsEowIq7qeJFSGTaHvDZ2iQUfDTETNcg5dY9/AtSAahq\nn1nhJEhJsRpwPwnhVOTV6AZiGNkZ3yZcm5vmAQ6yWlEjlrsAtMX08TYM+OWWt3B5\n2ld9r4YaQw79BXZo6Mzju1BtAoGAcm+WnHBXMzMeIplb3Cg9fUGVPeyHv3Zvv1OU\nzvFquHb3RvHWT/42USWTXYrLbIqrsd+db83fL60UfkVZNf80KJW+lRXj/Sfy7aBi\nW05rvOw0FFaN2z6+YBRDON9FEgQk7KegQ5VinZYnb8YIdBXQxszq0t4cly/RLJVJ\nycs9Yg8CgYBvxzGN6GlAEe4UYsnWxuS/HA1HVhlmefdPluIfoq1kbZZYcEazjn3r\n/gjLw1GJGdEtzh+cqJUrJVUG9dmCmXsK1HnS1jLQcyJ1WBThMI0XsXnSrTcd+rjY\nAbKm8Fh4dky1IoZunApYuCMEb6kRuOWQoiRx5MblwshOvsS47QQBCw==\n-----END RSA PRIVATE KEY-----"),
			payload: map[string]interface{}{
				"iss": "https://dune.io",
				"sub": "peter",
			},
			headers: map[string]interface{}{
				"alg": "RS256",
				"kid": "rsapem",
			},
			expectedResult: `eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYXBlbSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2R1bmUuaW8iLCJzdWIiOiJwZXRlciJ9.ahosNEhoRvDpG9r9fmOJD20qIq6zEHzTgOWlsSeCoYjKdGUKAJKmb0bdRwd_eys_3EuMJbZ1Bk8mTQpKvTWwpX9M3Ld_w6K_6UsJQUO1w8JZ-j6MvQ97jCUx-rzFYAl8jkYCil9T4uiOGhJ1btsKh5AIAe8uMHRem3cAe9zAsINwrYQpdbml0NHkhvLpWHBJhPmVbJbwfmy9i7nInvHf_f9YPTPgt8n2YJUpXRvcFLMwj08T-ChL-4xOMHztMOMZeby13F0fdKn6_OiNutq5LVOOIV2T0RhLJjRE7TToaf37cQYoyoWLKiB72JWdBEkBWN9dQt33v-DThZ1WlTThHQ`,
		},
		{
			desc: "RSA JWK signer",
			privateKey: []byte(`{
				"p": "z1Mklvta_Kw1q79PMhK7nHGVMIToyx9YPKjECQCAaDo02xCZCOBz-Tnv6NTwwsdoHKU4CjSf7TdD7_zpTaieyIkPRXPnMlSCMt626fD58EnIwvKJtTCwzHz8dbt7lH6ihq4xD4NNbE2xUiP6HjKGWyUM6RuNRSpfXPbEAmbslpU",
				"kty": "RSA",
				"q": "xH0o7t617m4Ec5lD2gMcFDH_VuNI-p2RvDAF60pOA-NRryJhwqJkbTCAeUAeaybh1Cv3cB3Tdl-10OpriS5rl62vmhVZUwaUhGstjwTUUBTTRkl7vIEwHWvWXtcpHaxbP2DV11OJhToAndbcVvAoOCmYKRtasbmlVletM9T9Nj8",
				"d": "k5r2JrDPCL5mBoTlfOPb1P45scJyXVF5ynLqfQX8hGhhYgvtg3AnTEzqbnTUdzSoMzIv0PUW6p1UGtw6AUL_Ts6bLL1xivgOIBKK1mmt0x9avl1JcpewELTT81FQ8f4E0ORXB-m9ZNYUhjH7Rs5hTI7zddnKQ5XJxMykSoEDjIdym-aptmUh0Y8UczQakSTkjopyZqQPu2vl4BMXxpXvj9pTaBRb_wG7vOdibdGlAnNRZosER5o7aK0o_bRwSeGEAQs-5A9AvJFt1twMJMEAowzih8r_fas0OXJ1dbs_QZfx35wqJ8MqwOImXLnoDxjOd2WAVc1hwCjkVpWUjki1aQ",
				"e": "AQAB",
				"use": "sig",
				"kid": "demojwtsigner",
				"qi": "b8cxjehpQBHuFGLJ1sbkvxwNR1YZZnn3T5biH6KtZG2WWHBGs4596_4Iy8NRiRnRLc4fnKiVKyVVBvXZgpl7CtR50tYy0HMidVgU4TCNF7F50q03Hfq42AGypvBYeHZMtSKGbpwKWLgjBG-pEbjlkKIkceTG5cLITr7EuO0EAQs",
				"dp": "hwoRuCHqZs_IeaC3ddcLyl-VHDBF7R_yejg2z-I6wSjAirup4kVIZNoe8NnaJBR8NMRM1yDl1j38C1IBqGqfWeEkSEmxGnA_CeFU5NXoBmIY2RnfJlybm-YBDrJaUSOWuwC0xfTxNgz45Za3cHnaV32vhhpDDv0FdmjozOO7UG0",
				"alg": "RS256",
				"dq": "cm-WnHBXMzMeIplb3Cg9fUGVPeyHv3Zvv1OUzvFquHb3RvHWT_42USWTXYrLbIqrsd-db83fL60UfkVZNf80KJW-lRXj_Sfy7aBiW05rvOw0FFaN2z6-YBRDON9FEgQk7KegQ5VinZYnb8YIdBXQxszq0t4cly_RLJVJycs9Yg8",
				"n": "nyEEwueLcSFRUSPdy9AL5Vf6X7QDuL8mFMOR2liM1LeluSHCSYIoN-h6xxMkwDfr6626EOhJVxMxeBuLaG-_3QWWjvicUdIpevj73U1jqQT7MaMPI3ms7rm0v1OHfabyLbrCjDniL_8Ym15H_RwVqF31kXIcKVqMtJWRWkeoOrSSqUq4h28rRDUi8HXUTAvSoQYnZ-J-sICME7G-ZYVJtIQObT6AjMuM_y54vCH8ViVE9aOQ2rV3Wi-TKEgiV9Ik1KB6EdzCB4CYK2HYy_OgheF0ggeWuwHOegBpVR4BqlQyZJKJyhKhWZhfYHmWkm_V-7KZtrWHoVQ_NhOAcT18qw"
			}`),
			payload: map[string]interface{}{
				"iss": "https://dune.io",
				"sub": "peter",
			},
			headers: map[string]interface{}{
				"alg": "RS256",
				"kid": "rsajwk",
			},
			expectedResult: `eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYWp3ayIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2R1bmUuaW8iLCJzdWIiOiJwZXRlciJ9.PX3GfzyydgV2-GCx13OD1A1a8IXYCIwrNyMy1u5u_QjqgPfXBzaaTATbV4PPR9j_jBGSY4iFk64Su1d-hxFHYwJ2Zqyep78rAnEqvM01W8i-cUoE5zRUMIYGMle66XpVW69PFOmgGywP5AuQGXAkbe57zlvanuaOGBMqdJ9kY3Ln5gmuuXebm8LD8odFzdi1vHhysRoNRuvkXsNrbjoj3TEE_GyHDrf5PposHviU6_hkcFwM6qQlk9nCI5v_SWlanZ79yKgM6lwzVFug9HE_RSpEMDadx0KOxpE-8RC5J5oxQeTOdbzYknNovl3pgoQskQENxzCoX9YvvV-UyaUSgg`,
		},
	}
	for _, c := range testCases {
		c := c
		t.Run(fmt.Sprintf("case=%s", c.desc), func(tt *testing.T) {
			signedJWT, err := Sign(context.Background(), c.privateKey, c.payload, c.headers)
			if err != nil {
				expected := ""
				if c.expectedError != nil {
					expected = c.expectedError.Error()
				}

				require.EqualError(tt, err, expected, "Error does not match.")
			}

			if c.expectedResult != "" {
				require.EqualValues(tt, c.expectedResult, signedJWT, "JWT does not match")
			}
		})
	}
}
