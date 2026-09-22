package predicates

import (
	"bytes"
	"strings"
	"testing"

	"tfreview/internal/plan"
	"tfreview/internal/planfix"
	"tfreview/internal/rules"
)

// Every fixture secret contains this marker, so a leak check can look for
// it in any detail string.
const secretMark = "SECRET"

type predCase struct {
	name   string
	build  func(*planfix.Plan)
	want   bool
	detail []string // substrings the detail must contain
}

func change(t *testing.T, build func(*planfix.Plan)) plan.Change {
	t.Helper()
	fix := planfix.New()
	build(fix)
	p, err := plan.Parse(bytes.NewReader(fix.JSON()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 1 {
		t.Fatalf("fixture has %d changes, want 1", len(p.Changes))
	}
	return p.Changes[0]
}

func runPredicate(t *testing.T, pred rules.Predicate, cases []predCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, detail := pred(change(t, tt.build))
			if got != tt.want {
				t.Errorf("matched = %v, want %v (detail %q)", got, tt.want, detail)
			}
			if !got && detail != "" {
				t.Errorf("detail %q on a non-match", detail)
			}
			for _, d := range tt.detail {
				if !strings.Contains(detail, d) {
					t.Errorf("detail %q does not contain %q", detail, d)
				}
			}
			if strings.Contains(detail, secretMark) {
				t.Errorf("detail leaks a sensitive value: %q", detail)
			}
		})
	}
}

func TestRegistryComplete(t *testing.T) {
	for _, name := range []string{
		"changes_sensitive_attribute", "disables_encryption", "removes_deletion_protection",
		"reduces_backup_retention", "was_moved", "widens_network_access",
	} {
		if Registry()[name] == nil {
			t.Errorf("predicate %s not registered", name)
		}
	}
}

func TestWasMoved(t *testing.T) {
	runPredicate(t, WasMoved, []predCase{
		{"moved", func(p *planfix.Plan) {
			p.Resource("aws_instance.new", "no-op").MovedFrom("aws_instance.old").Before(map[string]any{}).After(map[string]any{})
		}, true, []string{"moved from aws_instance.old"}},
		{"not moved", func(p *planfix.Plan) {
			p.Resource("aws_instance.new", "no-op").Before(map[string]any{}).After(map[string]any{})
		}, false, nil},
	})
}

func TestChangesSensitiveAttribute(t *testing.T) {
	pw := func(before, after any) func(*planfix.Plan) {
		return func(p *planfix.Plan) {
			p.Resource("aws_db_instance.main", "update").
				Before(map[string]any{"password": before, "size": "small"}).
				After(map[string]any{"password": after, "size": "large"}).
				BeforeSensitive(map[string]any{"password": true}).
				AfterSensitive(map[string]any{"password": true})
		}
	}
	replace := func(v any) func(*planfix.Plan) {
		return func(p *planfix.Plan) {
			p.Resource("aws_db_instance.main", "delete", "create").
				Before(map[string]any{"password": v, "identifier": "a"}).
				After(map[string]any{"password": v, "identifier": "b"}).
				BeforeSensitive(map[string]any{"password": true}).
				AfterSensitive(map[string]any{"password": true})
		}
	}
	wo := func(before, after int) func(*planfix.Plan) {
		return func(p *planfix.Plan) {
			p.Resource("aws_db_instance.main", "update").
				Before(map[string]any{"password_wo": nil, "password_wo_version": before, "size": "small"}).
				After(map[string]any{"password_wo": nil, "password_wo_version": after, "size": "large"}).
				AfterSensitive(map[string]any{"password_wo": true})
		}
	}
	runPredicate(t, ChangesSensitiveAttribute, []predCase{
		{"sensitive path changed on update", pw("old-SECRET", "new-SECRET"), true, []string{"sensitive value written: password"}},
		{"sensitive path unchanged on update", pw("same-SECRET", "same-SECRET"), false, nil},
		{"replace with identical sensitive value", replace("same-SECRET"), true, []string{"password"}},
		{"replace with null sensitive attribute", replace(nil), false, nil},
		{"nested sensitive path inside a block", func(p *planfix.Plan) {
			p.Resource("aws_instance.x", "update").
				Before(map[string]any{"cfg": []any{map[string]any{"token": "a-SECRET", "port": 1}}}).
				After(map[string]any{"cfg": []any{map[string]any{"token": "b-SECRET", "port": 1}}}).
				BeforeSensitive(map[string]any{"cfg": []any{map[string]any{"token": true}}}).
				AfterSensitive(map[string]any{"cfg": []any{map[string]any{"token": true}}})
		}, true, []string{"cfg.0.token"}},
		{"after_sensitive as root literal true on replace", func(p *planfix.Plan) {
			p.Resource("aws_db_instance.main", "delete", "create").
				Before(map[string]any{"password": "x-SECRET"}).
				After(map[string]any{"password": "x-SECRET"}).
				BeforeSensitive(true).AfterSensitive(true)
		}, true, []string{"password"}},
		{"data source", func(p *planfix.Plan) {
			p.Resource("data.aws_secretsmanager_secret_version.s", "update").
				Before(map[string]any{"secret_string": "a-SECRET"}).
				After(map[string]any{"secret_string": "b-SECRET"}).
				BeforeSensitive(map[string]any{"secret_string": true}).
				AfterSensitive(map[string]any{"secret_string": true})
		}, false, nil},
		{"password_wo_version changed on update", wo(1, 2), true,
			[]string{"password_wo_version changed (write-only value will be rewritten)"}},
		{"password_wo_version unchanged on update", wo(1, 1), false, nil},
		{"replace with unknown sensitive value", func(p *planfix.Plan) {
			p.Resource("aws_db_instance.main", "delete", "create").
				Before(map[string]any{"password": "x-SECRET"}).
				After(map[string]any{}).
				AfterUnknown(map[string]any{"password": true}).
				BeforeSensitive(map[string]any{"password": true}).
				AfterSensitive(map[string]any{"password": true})
		}, true, []string{"password"}},
		{"create is not a write of an existing secret", func(p *planfix.Plan) {
			p.Resource("aws_db_instance.main", "create").
				After(map[string]any{"password": "x-SECRET"}).
				AfterSensitive(map[string]any{"password": true})
		}, false, nil},
	})
}

func update(typ string, before, after map[string]any) func(*planfix.Plan) {
	return func(p *planfix.Plan) {
		p.Resource(typ+".x", "update").Before(before).After(after)
	}
}

func TestDisablesEncryption(t *testing.T) {
	m := func(kv ...any) map[string]any {
		out := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	runPredicate(t, DisablesEncryption, []predCase{
		{"rds storage_encrypted true to false", update("aws_db_instance", m("storage_encrypted", true), m("storage_encrypted", false)),
			true, []string{"storage_encrypted: true -> false"}},
		{"ebs encrypted true to false", update("aws_ebs_volume", m("encrypted", true), m("encrypted", false)), true, []string{"encrypted"}},
		{"efs encrypted false to true", update("aws_efs_file_system", m("encrypted", false), m("encrypted", true)), false, nil},
		{"elasticache at rest", update("aws_elasticache_replication_group",
			m("at_rest_encryption_enabled", true), m("at_rest_encryption_enabled", false)), true, []string{"at_rest_encryption_enabled"}},
		{"elasticache string-typed flag", update("aws_elasticache_replication_group",
			m("at_rest_encryption_enabled", "true"), m("at_rest_encryption_enabled", "false")), true, nil},
		{"elasticache in transit", update("aws_elasticache_replication_group",
			m("transit_encryption_enabled", true), m("transit_encryption_enabled", false)), true, []string{"transit_encryption_enabled"}},
		{"nested block flag", update("aws_instance",
			m("ebs_block_device", []any{m("encrypted", true, "size", 8)}),
			m("ebs_block_device", []any{m("encrypted", false, "size", 8)})), true, []string{"ebs_block_device.0.encrypted"}},
		{"true to null is not true to false", update("aws_db_instance", m("storage_encrypted", true), m("storage_encrypted", nil)), false, nil},
		{"flag unknown after", func(p *planfix.Plan) {
			p.Resource("aws_db_instance.x", "update").
				Before(m("storage_encrypted", true)).After(m()).AfterUnknown(m("storage_encrypted", true))
		}, false, nil},
		{"point_in_time_recovery is not encryption", update("aws_dynamodb_table",
			m("point_in_time_recovery", []any{m("enabled", true)}), m("point_in_time_recovery", []any{m("enabled", false)})), false, nil},
		{"kms_key_id to null", update("aws_db_instance", m("kms_key_id", "arn:aws:kms:k"), m("kms_key_id", nil)), true, []string{"kms_key_id removed"}},
		{"kms_key_arn to empty", update("aws_dynamodb_table",
			m("server_side_encryption", []any{m("enabled", true, "kms_key_arn", "arn:aws:kms:k")}),
			m("server_side_encryption", []any{m("enabled", true, "kms_key_arn", "")})), true, []string{"server_side_encryption.0.kms_key_arn removed"}},
		{"kms_master_key_id block removed", update("aws_s3_bucket_server_side_encryption_configuration",
			m("rule", []any{m("apply_server_side_encryption_by_default", []any{m("kms_master_key_id", "k", "sse_algorithm", "aws:kms")})}),
			m("rule", []any{})), true, []string{"kms_master_key_id removed"}},
		{"customer key to aws-managed alias", update("aws_db_instance",
			m("kms_key_id", "arn:aws:kms:us-east-1:111122223333:key/1234abcd"), m("kms_key_id", "alias/aws/rds")),
			true, []string{"kms_key_id: customer-managed key replaced by AWS-managed alias/aws/rds"}},
		{"customer key to aws-managed alias ARN", update("aws_ebs_volume",
			m("kms_key_id", "arn:aws:kms:us-east-1:111122223333:key/1234abcd"),
			m("kms_key_id", "arn:aws:kms:us-east-1:111122223333:alias/aws/ebs")),
			true, []string{"AWS-managed alias/aws/ebs"}},
		{"customer alias to aws-managed alias", update("aws_dynamodb_table",
			m("server_side_encryption", []any{m("enabled", true, "kms_key_arn", "alias/team-key")}),
			m("server_side_encryption", []any{m("enabled", true, "kms_key_arn", "alias/aws/dynamodb")})),
			true, []string{"server_side_encryption.0.kms_key_arn"}},
		{"aws-managed alias to another aws-managed alias", update("aws_db_instance",
			m("kms_key_id", "alias/aws/rds"), m("kms_key_id", "alias/aws/ebs")), false, nil},
		{"aws-managed alias to customer key", update("aws_db_instance",
			m("kms_key_id", "alias/aws/rds"), m("kms_key_id", "arn:aws:kms:us-east-1:111122223333:key/1234abcd")), false, nil},
		{"alias that only looks similar", update("aws_db_instance",
			m("kms_key_id", "k1"), m("kms_key_id", "alias/awsome/key")), false, nil},
		{"kms key changed to another key", update("aws_db_instance", m("kms_key_id", "k1"), m("kms_key_id", "k2")), false, nil},
		{"kms key added", update("aws_db_instance", m("kms_key_id", ""), m("kms_key_id", "k2")), false, nil},
		{"kms key unknown after", func(p *planfix.Plan) {
			p.Resource("aws_db_instance.x", "update").Before(m("kms_key_id", "k1")).After(m()).AfterUnknown(m("kms_key_id", true))
		}, false, nil},
		{"sensitive kms key is never read", func(p *planfix.Plan) {
			p.Resource("aws_db_instance.x", "update").
				Before(m("kms_key_id", "k-SECRET")).After(m("kms_key_id", nil)).
				BeforeSensitive(m("kms_key_id", true)).AfterSensitive(m("kms_key_id", true))
		}, false, nil},
	})
}

func TestRemovesDeletionProtection(t *testing.T) {
	runPredicate(t, RemovesDeletionProtection, []predCase{
		{"rds deletion_protection", update("aws_db_instance",
			map[string]any{"deletion_protection": true}, map[string]any{"deletion_protection": false}),
			true, []string{"deletion_protection: true -> false"}},
		{"dynamodb deletion_protection_enabled", update("aws_dynamodb_table",
			map[string]any{"deletion_protection_enabled": true}, map[string]any{"deletion_protection_enabled": false}),
			true, []string{"deletion_protection_enabled"}},
		{"lb enable_deletion_protection", update("aws_lb",
			map[string]any{"enable_deletion_protection": true}, map[string]any{"enable_deletion_protection": false}),
			true, []string{"enable_deletion_protection"}},
		{"s3 force_destroy false to true", update("aws_s3_bucket",
			map[string]any{"force_destroy": false}, map[string]any{"force_destroy": true}),
			true, []string{"force_destroy: false -> true"}},
		{"force_destroy true to false", update("aws_ecr_repository",
			map[string]any{"force_delete": false, "force_destroy": true}, map[string]any{"force_destroy": false}),
			false, nil},
		{"protection enabled", update("aws_db_instance",
			map[string]any{"deletion_protection": false}, map[string]any{"deletion_protection": true}), false, nil},
		{"unchanged", update("aws_db_instance",
			map[string]any{"deletion_protection": true, "size": 1}, map[string]any{"deletion_protection": true, "size": 2}), false, nil},
	})
}

func TestReducesBackupRetention(t *testing.T) {
	runPredicate(t, ReducesBackupRetention, []predCase{
		{"rds retention decreased", update("aws_db_instance",
			map[string]any{"backup_retention_period": 7}, map[string]any{"backup_retention_period": 3}),
			true, []string{"backup_retention_period: 7 -> 3"}},
		{"rds retention to zero", update("aws_db_instance",
			map[string]any{"backup_retention_period": 7}, map[string]any{"backup_retention_period": 0}),
			true, []string{"7 -> 0 (backups disabled)"}},
		{"retention increased", update("aws_db_instance",
			map[string]any{"backup_retention_period": 7}, map[string]any{"backup_retention_period": 14}), false, nil},
		{"elasticache snapshot_retention_limit", update("aws_elasticache_cluster",
			map[string]any{"snapshot_retention_limit": 5}, map[string]any{"snapshot_retention_limit": 1}),
			true, []string{"snapshot_retention_limit: 5 -> 1"}},
		{"retention unknown after", func(p *planfix.Plan) {
			p.Resource("aws_db_instance.x", "update").
				Before(map[string]any{"backup_retention_period": 7}).After(map[string]any{}).
				AfterUnknown(map[string]any{"backup_retention_period": true})
		}, false, nil},
		{"skip_final_snapshot false to true", update("aws_db_instance",
			map[string]any{"skip_final_snapshot": false}, map[string]any{"skip_final_snapshot": true}),
			true, []string{"skip_final_snapshot: false -> true"}},
		{"skip_final_snapshot true to false", update("aws_db_instance",
			map[string]any{"skip_final_snapshot": true}, map[string]any{"skip_final_snapshot": false}), false, nil},
		{"delete_automated_backups false to true", update("aws_db_instance",
			map[string]any{"delete_automated_backups": false}, map[string]any{"delete_automated_backups": true}),
			true, []string{"delete_automated_backups"}},
		{"dynamodb point in time recovery disabled", update("aws_dynamodb_table",
			map[string]any{"point_in_time_recovery": []any{map[string]any{"enabled": true}}},
			map[string]any{"point_in_time_recovery": []any{map[string]any{"enabled": false}}}),
			true, []string{"point_in_time_recovery.0.enabled: true -> false"}},
		{"other enabled flag ignored", update("aws_dynamodb_table",
			map[string]any{"ttl": []any{map[string]any{"enabled": true}}},
			map[string]any{"ttl": []any{map[string]any{"enabled": false}}}), false, nil},
		{"several at once", update("aws_db_instance",
			map[string]any{"backup_retention_period": 7, "skip_final_snapshot": false},
			map[string]any{"backup_retention_period": 1, "skip_final_snapshot": true}),
			true, []string{"backup_retention_period: 7 -> 1", "skip_final_snapshot: false -> true"}},
	})
}

func TestDisablesEncryptionAliasDetailOmitsAccount(t *testing.T) {
	c := change(t, update("aws_ebs_volume",
		map[string]any{"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/1234abcd"},
		map[string]any{"kms_key_id": "arn:aws:kms:us-east-1:111122223333:alias/aws/ebs"}))
	ok, detail := DisablesEncryption(c)
	if !ok || strings.Contains(detail, "111122223333") || strings.Contains(detail, "us-east-1") {
		t.Errorf("matched %v, detail %q: want a match naming only the alias", ok, detail)
	}
}
