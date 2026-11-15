package main

import rego.v1

deploy_job_with(reference) := {"jobs": {"deploy": {
	"permissions": {"contents": "read", "id-token": "write"},
	"steps": [{"uses": reference}],
}}}

test_tag_pinned_action_in_id_token_job_is_denied if {
	count(deny) > 0 with input as deploy_job_with("google-github-actions/auth@v2")
}

test_sha_pinned_action_in_id_token_job_passes if {
	count(deny) == 0 with input as deploy_job_with("google-github-actions/auth@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f")
}

test_workflow_level_id_token_counts if {
	count(deny) > 0 with input as {
		"permissions": {"id-token": "write"},
		"jobs": {"deploy": {"steps": [{"uses": "google-github-actions/setup-gcloud@v2"}]}},
	}
}

test_tag_pinned_action_without_id_token_only_warns if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"uses": "actions/checkout@v4"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) > 0 with input as policy_input
}

test_local_action_is_not_flagged if {
	policy_input := {"jobs": {"build": {"permissions": {"id-token": "write"}, "steps": [{"uses": "./.github/actions/setup"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) == 0 with input as policy_input
}

test_unpinned_pip_install_warns if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"run": "python -m pip install --disable-pip-version-check semgrep"}]}}}
	count(warn) > 0 with input as policy_input
}

test_pinned_pip_install_passes if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"run": "python -m pip install --disable-pip-version-check semgrep==1.97.0\npip install -r requirements.txt"}]}}}
	count(warn) == 0 with input as policy_input
}

# hub#495 rule gap A2: a docker:// image is exempt only when it is pinned by digest.
test_docker_tag_in_id_token_job_is_denied if {
	count(deny) > 0 with input as deploy_job_with("docker://alpine:3.20")
}

test_docker_digest_in_id_token_job_passes if {
	count(deny) == 0 with input as deploy_job_with(concat("", ["docker://alpine@sha256:", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]))
}

test_docker_tag_without_id_token_only_warns if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"uses": "docker://alpine:3.20"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) > 0 with input as policy_input
}

# hub#495 rule gap A2: a job-level `uses:` calls a reusable workflow with the job's permissions.
test_tag_pinned_reusable_workflow_in_id_token_job_is_denied if {
	count(deny) > 0 with input as {"jobs": {"deploy": {
		"permissions": {"id-token": "write"},
		"uses": "some-org/workflows/.github/workflows/deploy.yml@v1",
	}}}
}

test_sha_pinned_reusable_workflow_in_id_token_job_passes if {
	count(deny) == 0 with input as {"jobs": {"deploy": {
		"permissions": {"id-token": "write"},
		"uses": "some-org/workflows/.github/workflows/deploy.yml@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f",
	}}}
}

test_tag_pinned_reusable_workflow_without_id_token_only_warns if {
	policy_input := {"jobs": {"call": {"permissions": {"contents": "read"}, "uses": "some-org/workflows/.github/workflows/ci.yml@main"}}}
	count(deny) == 0 with input as policy_input
	count(warn) > 0 with input as policy_input
}

test_local_reusable_workflow_is_not_flagged if {
	policy_input := {"jobs": {"call": {"permissions": {"id-token": "write"}, "uses": "./.github/workflows/build.yml"}}}
	count(deny) == 0 with input as policy_input
	count(warn) == 0 with input as policy_input
}

# hub#495 rule gap A2: a local composite action runs with its caller's token, so an unpinned step is denied.
test_tag_pinned_step_in_composite_action_is_denied if {
	count(deny) > 0 with input as {"runs": {"using": "composite", "steps": [{"uses": "actions/setup-node@v4"}]}}
}

test_docker_tag_in_composite_action_is_denied if {
	count(deny) > 0 with input as {"runs": {"using": "composite", "steps": [{"uses": "docker://alpine:3.20"}]}}
}

test_sha_pinned_step_in_composite_action_passes if {
	count(deny) == 0 with input as {"runs": {"using": "composite", "steps": [
		{"uses": "actions/setup-node@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f"},
		{"run": "echo ok", "shell": "bash"},
	]}}
}
