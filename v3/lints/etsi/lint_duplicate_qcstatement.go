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

package etsi

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_duplicate_qcstatement",
			Description:   "Checks for duplicated QcStatements, returning error if any are found",
			Citation:      "ETSI EN 319 412-5 v2.6.0, clause QCS-4.1-02A",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiEn319_412_5_V2_6_0_Date,
		},
		Lint: NewDuplicateQCStatement,
	})
}

type DuplicateQCStatement struct{}

func NewDuplicateQCStatement() lint.LintInterface {
	return &DuplicateQCStatement{}
}

func (l *DuplicateQCStatement) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.QcStateOid)
}

func (l *DuplicateQCStatement) Execute(c *x509.Certificate) *lint.LintResult {

	foundStatements := make(map[string]bool)

	for _, statId := range c.QCStatements.StatementIDs {
		if foundStatements[statId] {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "The qcStatements extension shall not include more than one instance of a particular qcStatement",
			}
		}
		foundStatements[statId] = true
	}
	return &lint.LintResult{Status: lint.Pass}
}
