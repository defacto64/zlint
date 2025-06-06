/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

// Used to check parsed info from certificate for compliance

package zlint

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	_ "github.com/zmap/zlint/v3/lints/apple"
	_ "github.com/zmap/zlint/v3/lints/cabf_br"
	_ "github.com/zmap/zlint/v3/lints/cabf_cs_br"
	_ "github.com/zmap/zlint/v3/lints/cabf_ev"
	_ "github.com/zmap/zlint/v3/lints/cabf_smime_br"
	_ "github.com/zmap/zlint/v3/lints/community"
	_ "github.com/zmap/zlint/v3/lints/etsi"
	_ "github.com/zmap/zlint/v3/lints/mozilla"
	_ "github.com/zmap/zlint/v3/lints/rfc"
	"golang.org/x/crypto/ocsp"
)

const Version int64 = 3

// LintCertificate runs all registered lints on c using default options,
// producing a ResultSet.
//
// Using LintCertificate(c) is equivalent to calling LintCertificateEx(c, nil).
func LintCertificate(c *x509.Certificate) *ResultSet {
	// Run all lints from the global registry
	return LintCertificateEx(c, nil)
}

// LintCertificateEx runs lints from the provided registry on c producing
// a ResultSet. Providing an explicit registry allows the caller to filter the
// lints that will be run. (See lint.Registry.Filter())
//
// If registry is nil then the global registry of all lints is used and this
// function is equivalent to calling LintCertificate(c).
func LintCertificateEx(c *x509.Certificate, registry lint.Registry) *ResultSet {
	if c == nil {
		return nil
	}
	if registry == nil {
		registry = lint.GlobalRegistry()
	}
	res := new(ResultSet)
	res.executeCertificate(c, registry)
	res.Version = Version
	res.Timestamp = time.Now().Unix()
	return res
}

// LintRevocationList runs all registered lints on r using default options,
// producing a ResultSet.
//
// Using LintRevocationList(r) is equivalent to calling LintRevocationListEx(r, nil).
func LintRevocationList(r *x509.RevocationList) *ResultSet {
	return LintRevocationListEx(r, nil)
}

// LintRevocationListEx runs lints from the provided registry on r producing
// a ResultSet. Providing an explicit registry allows the caller to filter the
// lints that will be run. (See lint.Registry.Filter())
//
// If registry is nil then the global registry of all lints is used and this
// function is equivalent to calling LintRevocationList(r).
func LintRevocationListEx(r *x509.RevocationList, registry lint.Registry) *ResultSet {
	if r == nil {
		return nil
	}
	if registry == nil {
		registry = lint.GlobalRegistry()
	}
	res := new(ResultSet)
	res.executeRevocationList(r, registry)
	res.Version = Version
	res.Timestamp = time.Now().Unix()
	return res
}

// LintOcspResponse runs all registered lints on o using default options,
// producing a ResultSet.
//
// Using LintOcspResponse(o) is equivalent to calling LintOcspResponseEx(o, nil).
func LintOcspResponse(o *ocsp.Response) *ResultSet {
	return LintOcspResponseEx(o, nil)
}

// LintOcspResponseEx runs lints from the provided registry on o producing
// a ResultSet. Providing an explicit registry allows the caller to filter the
// lints that will be run. (See lint.Registry.Filter())
//
// If registry is nil then the global registry of all lints is used and this
// function is equivalent to calling LintOcspResponse(o).
func LintOcspResponseEx(o *ocsp.Response, registry lint.Registry) *ResultSet {
	if o == nil {
		return nil
	}
	if registry == nil {
		registry = lint.GlobalRegistry()
	}
	res := new(ResultSet)
	res.executeOcspResponse(o, registry)
	res.Version = Version
	res.Timestamp = time.Now().Unix()
	return res
}
