# RAKSHA rules of engagement as policy code (Open Policy Agent). A second, independent statement of
# the deploy rule in raksha/roe.py: when RAKSHA_OPA=1 and `opa` is present, a deploy is allowed only
# if BOTH this policy and the built-in rule allow it; an OPA error refuses (fail closed).
package raksha.roe

import rego.v1

default allow := false

signers := {lower(trim_space(s)) | some s in input.signers; trim_space(s) != ""}

allow if {
	input.verified
	input.effective == 3
	not input.two_person
}

allow if {
	input.verified
	input.effective == 2
	not input.two_person
	count(signers) >= 1
}

allow if {
	input.verified
	input.effective >= 2
	input.two_person
	count(signers) >= 2
}
