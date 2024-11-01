#-----------------------------------------------------------------------------
# High level policy for controlling access to Kafka.
#
# * Deny operations by default.
# * Allow operations if no explicit denial.
#
# The kafka-authorizer-opa plugin will query OPA for decisions at
# /kafka/authz/allow. If the policy decision is _true_ the request is allowed.
# If the policy decision is _false_ the request is denied.
#-----------------------------------------------------------------------------
package kafka.authz

default allow = false

allow {
  not deny
}

deny {
  not admin_policy
  not xptucer_policy
  not consumer_policy
  not idempotent_xptucer_policy
  not consumer_group_policy
  not plaintext_xptucer_policy
  not plaintext_consumer_policy
}

#-----------------------------------
# Helpers for checking topic access.
#-----------------------------------

admin_policy {
  input.requestContext.clientAddress == whitelist_admins[_]
}

idempotent_xptucer_policy {
  xptucer_topics_map[input.requestContext.principal.name]
  is_idempotent_xptucer
}

plaintext_xptucer_policy {
  topics := plaintext_xptucer_topics_map[input.requestContext.clientAddress]
  topic_name == topics[_]
  is_xptucer
}

xptucer_policy {
  topics := xptucer_topics_map[input.requestContext.principal.name]
  topic_name == topics[_]
  is_xptucer
}

plaintext_consumer_policy {
  topics := plaintext_consumer_topics_map[input.requestContext.clientAddress]
  topic_name == topics[_]
  is_consumer
}

consumer_policy {
  topics := consumer_topics_map[input.requestContext.principal.name]
  topic_name == topics[_]
  is_consumer
}

consumer_group_policy {
  consumer_topics_map[input.requestContext.principal.name]
  is_consumer_group
}

#-----------------------------------------------------------------------------
# ol structures for controlling access to topics. In real-world deployments,
# these ol structures could be loaded into OPA as raw JSON ol. The JSON
# ol could be pulled from external sources like AD, Git, etc.
#-----------------------------------------------------------------------------

## Client to topic mappings
plaintext_xptucer_topics_map := {
  "200.200.200.200": [
    "x-ert-eq",
    "x-pqa-eq"
  ]
}

xptucer_topics_map := {
  "OU=team,O=domain,C=US,ST=CJ,CN=team-kafka-monitor.clients.kafka.dev.team.domain.com": [
    "kafka-monitor-topic"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=usteamdvadm01x.sub-domain.domain.com": [
    "perftest"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=usteamdvol01x.sub-domain.domain.com": [
    "team-opa"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=dw-yb-publisher.clients.kafka.dev.team.domain.com": [
    "qbn-dfg-dev",
    "qbn-dfg-qa" 
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=core-stream-publisher.clients.kafka.dev.team.domain.com": [
    "nfi-dfg-clob-dev",
    "nfi-dfg-clob-audit-dev",
    "nfi-hedgestream-clob-dev"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=olp-stream.clients.kafka.dev.team.domain.com": [
    "olp-hourly-tax-preds",
    "olp-hourly-tax-preds-poc",
    "olp-tax-preds-tre-bm-poc",
    "olp-tax-preds-tre-bm"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=pl-ar-xptucer.clients.kafka.dev.team.domain.com": [
    "pl-ar",
    "pl-ar-test",
    "pl-ar-demo",
    "pl-ar-perf",
    "pl-ar-psc",
    "pl-ar-dev1",
    "pl-ar-dev2",
    "pl-ar-dev3",
    "pl-ar-dev4",
    "pl-ar-dev5",
    "pl-ar-dev6",
    "pl-ar-qa",
    "pl-ar-qa1",
    "pl-ar-qa2",
    "pl-ar-mbs",
    "pl-ar-mbs-test",
    "pl-ar-mbs-demo",
    "pl-ar-mbs-perf",
    "pl-ar-mbs-psc",
    "pl-ar-mbs-dev1",
    "pl-ar-mbs-dev2",
    "pl-ar-mbs-dev3",
    "pl-ar-mbs-dev4",
    "pl-ar-mbs-dev5",
    "pl-ar-mbs-dev6",
    "pl-ar-mbs-qa",
    "pl-ar-mbs-qa1",
    "pl-ar-mbs-qa2",
    "pl-ar-otr",
    "pl-ar-otr-test",
    "pl-ar-otr-demo",
    "pl-ar-otr-perf",
    "pl-ar-otr-psc",
    "pl-ar-otr-dev1",
    "pl-ar-otr-dev2",
    "pl-ar-otr-dev3",
    "pl-ar-otr-dev4",
    "pl-ar-otr-dev5",
    "pl-ar-otr-dev6",
    "pl-ar-otr-qa",
    "pl-ar-otr-qa1",
    "pl-ar-otr-qa2",
    "pl-ar-ikd-test",
    "pl-ar-ikd-demo",
    "pl-ar-ikd-perf",
    "pl-ar-ikd-psc",
    "pl-ar-ikd-dev1",
    "pl-ar-ikd-dev2",
    "pl-ar-ikd-dev3",
    "pl-ar-ikd-dev4",
    "pl-ar-ikd-dev5",
    "pl-ar-ikd-dev6",
    "pl-ar-ikd-qa",
    "pl-ar-ikd-qa1",
    "pl-ar-ikd-qa2",
    "pl-byu-mbs",
    "pl-byu-mbs-demo",
    "pl-byu-mbs-dev1",
    "pl-byu-mbs-dev2",
    "pl-byu-mbs-dev3",
    "pl-byu-mbs-dev4",
    "pl-byu-mbs-dev5",
    "pl-byu-mbs-dev6",
    "pl-byu-mbs-devp",
    "pl-byu-mbs-devx",
    "pl-byu-mbs-perf",
    "pl-byu-mbs-psc",
    "pl-byu-mbs-qa",
    "pl-byu-mbs-qa1",
    "pl-byu-mbs-qa2",
    "pl-byu-mbs-test",
    "pl-byu-otr",
    "pl-byu-otr-demo",
    "pl-byu-otr-dev1",
    "pl-byu-otr-dev2",
    "pl-byu-otr-dev3",
    "pl-byu-otr-dev4",
    "pl-byu-otr-dev5",
    "pl-byu-otr-dev6",
    "pl-byu-otr-devp",
    "pl-byu-otr-devx",
    "pl-byu-otr-perf",
    "pl-byu-otr-psc",
    "pl-byu-otr-qa",
    "pl-byu-otr-qa1",
    "pl-byu-otr-qa2",
    "pl-byu-otr-test",
    "pl-er-mbs-dev6",
    "pl-er-efp-dev6",
    "pl-er-agcy-dev6",
    "pl-er-bill-dev6",
    "pl-er-cmbs-dev6",
    "pl-er-trsye-dev6",
    "pl-er-trsy-dev6",
    "pl-er-irs-dev6",
    "pl-er-irsv-dev6",
    "pl-er-repo-dev6",
    "pl-er-otr-dev6",
    "pl-er-ikd-dev6",
    "pl-er-otrc-dev6"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-eqosite-xptucer.clients.kafka.dev.team.domain.com": [
    "x-ikd-dlr",
    "x-ikd-eq",
    "treasury-direct-ref"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-eu-olp-ol-test.clients.kafka.dev.team.domain.com": [
    "x-eu-olp-ol-test"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=team-tba-mbs.clients.kafka.dev.team.domain.com": [
    "x-aery-details-tba-mbs"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=ol-x-ice-ref-price.clients.kafka.dev.team.domain.com": [
    "ol-ice-ref-price",
    "ol-ice-ref-price-lite"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-olp-ol.clients.kafka.dev.team.domain.com": [
    "ol-indices-refinitiv",
    "ol-ice-ref-price",
    "ol-ice-ref-price-lite",
    "x-adn-eq",
    "x-adn-dlr",
    "x-agcy-eq",
    "x-agcy-dlr",
    "x-agcy-bnmee",
    "x-bond-futures",
    "x-can-eq",
    "x-can-dlr",
    "x-cp-dlr",
    "x-cp-eq",
    "x-dsup-eq",
    "x-dsup-dlr",
    "x-dwust-eq",
    "x-der-eq",
    "x-der-eq-bnmee",
    "x-der-dlr",
    "x-der-bnmee",
    "x-der-bnmee-unthrottled",
    "x-der-bnmee2",
    "x-der-bnmee3",
    "x-ecp-dlr",
    "x-eeqo-eq",
    "x-eeqo-bnmee",
    "x-etf-bnmee",
    "x-etfx-bnmee",
    "x-eu-cds-eq",
    "x-eu-cds-bnmee",
    "x-eu-cdssn-eq",
    "x-eu-cdssn-bnmee",
    "x-eurp-bnmee",
    "x-muni-io",
    "x-eutre-io",
    "x-eutre-io-staging",
    "x-eutre-eq",
    "x-eutre-dlr",
    "x-eutre-bnm",
    "x-ikd-dlr-unthrottled",
    "x-ikd-bnmee",
    "x-ikd-bnmee-unthrottled",
    "x-ikd-staq",
    "x-fx-refinitiv",
    "x-gcurve",
    "x-irs-eq",
    "x-irs-eq-bnmee",
    "x-irs-dlr",
    "x-irs-bnmee",
    "x-irs-bnmee-unthrottled",
    "x-irs-bnmee2",
    "x-irs-bnmee3",
    "x-jgb-eq",
    "x-jgb-dlr",
    "x-jgb-bnmee",
    "x-mbspool-bnmee",
    "x-pfan-eq",
    "x-pfan-dlr",
    "x-rtequity-refinitiv",
    "x-rtequity-refinitiv-test",
    "x-ert-eq",
    "x-ert-dlr",
    "x-swapcurve",
    "x-tbambs-eq",
    "x-tbambs-dlr",
    "x-aery-details",
    "x-aery-details-stg50",
    "x-trsy-staq", 
    "x-us-cds-eq",
    "x-us-cds-bnmee",
    "x-us-cdssn-eq",
    "x-us-cdssn-bnmee",
    "x-ustre-io",
    "x-ustre-io-pp",
    "x-ustre-io-partitioned",
    "x-ustre-io-snapshot",
    "x-ustre-io-snapshot-pp",
    "x-ustre-eq",
    "x-ustre-dlr",
    "x-ustre-bnm",
    "x-pqa-eq",
    "x-pqa-eq-debug",
    "x-pqa-dlr",
    "x-pqa-dlr-debug", 
    "x-pqa-bnmee",
    "x-yswp-eq",
    "x-yswp-eq-bnmee",
    "x-yswp-dlr",
    "x-yswp-bnmee",
    "x-yswp-bnmee-unthrottled",
    "x-yswp-bnmee2",
    "x-yswp-bnmee3",
    "qwe-abc-bnmee",
    "qwe-abc-bnmee-snapshot",
    "eef-btds-enriched",
    "eef-btds-raw",
    "eef-atds-enriched",
    "eef-atds-raw",
    "eef-spds-enriched",
    "eef-spds-raw"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=dsa-eqosite-consumer.clients.kafka.dev.team.domain.com": [
    "dsa-ikd-eqwidth",
    "dsa-beta-inav-etf",
    "dsa-inav-etf-config"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=dw-actives.clients.kafka.dev.team.domain.com": [
    "dw-actives-byu",
    "dw-actives-aerys"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=eef-feed-xptucer.clients.kafka.dev.team.domain.com": [
    "twnbtddb-eef-realtime"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-ui.clients.kafka.dev.team.domain.com": [
    "x-ui"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=tre-bnm.clients.kafka.dev.team.domain.com": [
    "tre-all-bnm-prices",
    "tre-filtered-bnm-prices",
    "tre-all-bnm-prices-pre-xpt",
    "tre-filtered-bnm-prices-pre-xpt",
    "tre-bnm-intermediate-df-bnm-prices", 
    "tre-bnm-intermediate-df-bnm-session-ranked-post-oc3",
    "us-stg-bnm-oms-abc-event"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=platform-logs.clients.kafka.dev.team.domain.com": [
    "x-logs-dev-aerydd-trdsnap" 
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=non-xpt.docker.x.domain.com": [
    "x-etf-bnm-ne-dsgt-dev",
    "x-etf-bnm-ne-dsgt-demo",
    "x-etf-bnm-ne-dsgt-dlrdev",
    "x-etf-bnm-ne-dsgt-stg",
    "x-etf-bnm-ne-dsgt-stg50",
    "x-nli"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=team-ol-quality.clients.kafka.dev.team.domain.com": [
    "x-ikd-eq-xfmd",
    "x-ikd-dlr-xfmd",
    "x-ikd-dlr-unthrottled-xfmd",
    "x-ikd-bnmee-xfmd",
    "dev-bnm-oms-abc-event",
    "us-stg-bnm-oms-abc-event",
    "x-sbox-bnm-oms-eucr-session"
  ]
}

plaintext_consumer_topics_map := {
  # Temporary access for Vandana Menon to debug malformed messages
  "200.200.200.200": [
    "dlq-x-ert-eq",
    "dlq-x-pqa-eq",
    "x-ert-eq",
    "x-pqa-eq"
  ]
}

consumer_topics_map := {
  "OU=team,O=domain,C=US,ST=CJ,CN=team-kafka-monitor.clients.kafka.dev.team.domain.com": [
    "kafka-monitor-topic"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=usteamdvadm01x.sub-domain.domain.com": [
    "perftest"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=usteamdvol01x.sub-domain.domain.com": [
    "team-opa"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=core-stream-publisher.clients.kafka.dev.team.domain.com": [
    "nfi-dfg-clob-dev",
    "nfi-dfg-clob-audit-dev",
    "nfi-hedgestream-clob-dev",
    "dlq-nfi-dfg-clob-dev",
    "dlq-nfi-dfg-clob-audit-dev",
    "dlq-nfi-hedgestream-clob-dev"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=pl-ar-xptucer.clients.kafka.dev.team.domain.com": [
    "pl-ar",
    "pl-ar-test",
    "pl-ar-demo",
    "pl-ar-perf",
    "pl-ar-psc",
    "pl-ar-dev1",
    "pl-ar-dev2",
    "pl-ar-dev3",
    "pl-ar-dev4",
    "pl-ar-dev5",
    "pl-ar-dev6",
    "pl-ar-qa",
    "pl-ar-qa1",
    "pl-ar-qa2",
    "pl-ar-mbs",
    "pl-ar-mbs-test",
    "pl-ar-mbs-demo",
    "pl-ar-mbs-perf",
    "pl-ar-mbs-psc",
    "pl-ar-mbs-dev1",
    "pl-ar-mbs-dev2",
    "pl-ar-mbs-dev3",
    "pl-ar-mbs-dev4",
    "pl-ar-mbs-dev5",
    "pl-ar-mbs-dev6",
    "pl-ar-mbs-qa",
    "pl-ar-mbs-qa1",
    "pl-ar-mbs-qa2",
    "pl-ar-otr",
    "pl-ar-otr-test",
    "pl-ar-otr-demo",
    "pl-ar-otr-perf",
    "pl-ar-otr-psc",
    "pl-ar-otr-dev1",
    "pl-ar-otr-dev2",
    "pl-ar-otr-dev3",
    "pl-ar-otr-dev4",
    "pl-ar-otr-dev5",
    "pl-ar-otr-dev6",
    "pl-ar-otr-qa",
    "pl-ar-otr-qa1",
    "pl-ar-otr-qa2",
    "pl-ar-ikd-test",
    "pl-ar-ikd-demo",
    "pl-ar-ikd-perf",
    "pl-ar-ikd-psc",
    "pl-ar-ikd-dev1",
    "pl-ar-ikd-dev2",
    "pl-ar-ikd-dev3",
    "pl-ar-ikd-dev4",
    "pl-ar-ikd-dev5",
    "pl-ar-ikd-dev6",
    "pl-ar-ikd-qa",
    "pl-ar-ikd-qa1",
    "pl-ar-ikd-qa2",
    "pl-byu-mbs",
    "pl-byu-mbs-demo",
    "pl-byu-mbs-dev1",
    "pl-byu-mbs-dev2",
    "pl-byu-mbs-dev3",
    "pl-byu-mbs-dev4",
    "pl-byu-mbs-dev5",
    "pl-byu-mbs-dev6",
    "pl-byu-mbs-devp",
    "pl-byu-mbs-devx",
    "pl-byu-mbs-perf",
    "pl-byu-mbs-psc",
    "pl-byu-mbs-qa",
    "pl-byu-mbs-qa1",
    "pl-byu-mbs-qa2",
    "pl-byu-mbs-test",
    "pl-byu-otr",
    "pl-byu-otr-demo",
    "pl-byu-otr-dev1",
    "pl-byu-otr-dev2",
    "pl-byu-otr-dev3",
    "pl-byu-otr-dev4",
    "pl-byu-otr-dev5",
    "pl-byu-otr-dev6",
    "pl-byu-otr-devp",
    "pl-byu-otr-devx",
    "pl-byu-otr-perf",
    "pl-byu-otr-psc",
    "pl-byu-otr-qa",
    "pl-byu-otr-qa1",
    "pl-byu-otr-qa2",
    "pl-byu-otr-test",
    "pl-er-mbs-dev6",
    "pl-er-efp-dev6",
    "pl-er-agcy-dev6",
    "pl-er-bill-dev6",
    "pl-er-cmbs-dev6",
    "pl-er-trsye-dev6",
    "pl-er-trsy-dev6",
    "pl-er-irs-dev6",
    "pl-er-irsv-dev6",
    "pl-er-repo-dev6",
    "pl-er-otr-dev6",
    "pl-er-ikd-dev6",
    "pl-er-otrc-dev6"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-eqosite-xptucer.clients.kafka.dev.team.domain.com": [
    "x-ikd-dlr",
    "x-ikd-eq",
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-eu-olp-ol-test.clients.kafka.dev.team.domain.com": [
    "x-eu-olp-ol-test"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-olp-ol.teamwork.kafka.dev.team.domain.com": [
    "olp-tax-preds-tre-bm"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-olp-ol-test.teamwork.kafka.dev.team.domain.com": [
    "olp-tax-preds-tre-bm"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-olp-ol.clients.kafka.dev.team.domain.com": [
    "ol-indices-refinitiv",
    "ol-ice-ref-price",
    "ol-ice-ref-price-lite",
    "x-adn-eq",
    "x-adn-dlr",
    "x-agcy-eq",
    "x-agcy-dlr",
    "x-agcy-bnmee",
    "x-bond-futures",
    "x-can-eq",
    "x-can-dlr",
    "x-cp-dlr",
    "x-cp-eq",
    "x-der-eq",
    "x-der-eq-bnmee",
    "x-der-dlr",
    "x-der-bnmee",
    "x-der-bnmee-unthrottled",
    "x-der-bnmee2",
    "x-der-bnmee3",
    "x-ecp-dlr",
    "x-eeqo-bnmee",
    "x-etf-bnmee",
    "x-etf-bnm-ne-dsgt-demo",
    "x-etf-bnm-ne-dsgt-dev",
    "x-etf-bnm-ne-dsgt-dlrdev",
    "x-etf-bnm-ne-dsgt-stg",
    "x-etf-bnm-ne-dsgt-stg50",
    "x-etfx-bnmee",
    "x-eu-cds-eq",
    "x-eu-cds-bnmee",
    "x-eu-cdssn-eq",
    "x-eu-cdssn-bnmee",
    "x-muni-io",
    "x-eutre-io",
    "x-eutre-io-staging",
    "x-eutre-eq",
    "x-eutre-dlr",
    "x-ikd-dlr-unthrottled",
    "x-ikd-bnmee",
    "x-ikd-bnmee-unthrottled",
    "x-ikd-bnmee-audit",
    "x-ikd-staq",
    "x-fx-refinitiv",
    "x-gcurve",
    "x-irs-eq",
    "x-irs-eq-bnmee",
    "x-irs-dlr",
    "x-irs-bnmee",
    "x-irs-bnmee-unthrottled",
    "x-irs-bnmee2 ",
    "x-irs-bnmee3 ",
    "x-jgb-eq",
    "x-jgb-dlr",
    "x-jgb-bnmee",
    "x-mbspool-bnmee",
    "x-rtequity-refinitiv",
    "x-rtequity-refinitiv-test",
    "x-swapcurve",
    "x-tbambs-eq",
    "x-tbambs-dlr",
    "x-aery-details",
    "x-aery-details-2wk-temp",
    "x-aery-details-tba-mbs",
    "x-trsy-staq", 
    "x-us-cds-eq",
    "x-us-cds-bnmee",
    "x-us-cdssn-eq",
    "x-us-cdssn-bnmee",
    "x-ustre-io",
    "x-ustre-io-partitioned",
    "x-ustre-eq",
    "x-ustre-dlr",
    "x-ustre-bnm",
    "x-pqa-eq",
    "x-pqa-eq-debug",
    "x-pqa-dlr",
    "x-pqa-dlr-debug",
    "x-pqa-bnmee",
    "x-yswp-eq",
    "x-yswp-eq-bnmee",
    "x-yswp-dlr",
    "x-yswp-bnmee",
    "x-yswp-bnmee-unthrottled",
    "x-yswp-bnmee2",
    "x-yswp-bnmee3",
    "olp-hourly-tax-preds",
    "olp-tax-preds-tre-bm",
    "qwe-abc-bnmee",
    "qwe-abc-bnmee-snapshot", 
    "us-xpt-dsa-beta-inav-etf",
    "us-xpt-dsa-inav-etf-equities-premium",
    "us-xpt-dsa-inav-etf-equities-standard",
    "us-xpt-dsa-inav-etf-standard",
    "us-xpt-x-ustre-bnm",
    "eef-btds-enriched",
    "eef-btds-raw",
    "eef-atds-enriched",
    "eef-atds-raw",
    "eef-spds-enriched",
    "eef-spds-raw"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=dsa-eqosite-consumer.clients.kafka.dev.team.domain.com": [
    "dsa-ikd-eqwidth",
    "x-ikd-dlr",
    "x-ikd-dlr-unthrottled",
    "x-ikd-eq",
    "x-eutre-dlr",
    "x-eutre-eq",
    "x-pqa-eq",
    "x-pqa-dlr",
    "x-ustre-eq",
    "x-ustre-dlr",
    "x-ustre-io",
    "x-pqa-bnmee",
    "x-dsup-eq",
    "x-dsup-dlr",
    "x-pfan-eq",
    "x-pfan-dlr",
    "x-ert-eq",
    "x-ert-dlr",
    "x-ustre-bnm",
    "dsa-beta-inav-etf"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=dw-actives.clients.kafka.dev.team.domain.com": [
    "dw-actives-byu",
    "dw-actives-aerys",
    "pl-ar",
    "pl-ar-test",
    "pl-ar-demo",
    "pl-ar-psc",
    "pl-ar-qa"
  ], 
  "OU=team,O=domain,C=US,ST=CJ,CN=x-ui.clients.kafka.dev.team.domain.com": [
    "x-ui"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=team-ol-quality.clients.kafka.dev.team.domain.com": [
    "twnbtddb-eef-realtime",
    "dsa-ikd-eqwidth",
    "dw-actives-byu",
    "dw-actives-aerys",
    "pl-ar",
    "x-ikd-eq",
    "x-ikd-dlr",
    "x-ikd-dlr-unthrottled",
    "x-ikd-bnmee",
    "x-ikd-eq-xfmd",
    "x-ikd-dlr-xfmd",
    "x-ikd-dlr-unthrottled-xfmd",
    "x-ikd-bnmee-xfmd",
    "x-eutre-eq",
    "x-eutre-dlr",
    "x-eutre-bnm",
    "x-pqa-eq",
    "x-pqa-dlr",
    "x-ustre-eq",
    "x-ustre-dlr",
    "x-ustre-io",
    "x-pqa-bnmee",
    "x-dsup-eq",
    "x-dsup-dlr",
    "x-pfan-eq",
    "x-pfan-dlr",
    "x-ert-eq",
    "x-ert-dlr",
    "x-der-eq",
    "x-der-dlr",
    "x-der-bnmee",
    "x-der-bnmee-unthrottled",
    "x-yswp-eq",
    "x-yswp-dlr",
    "x-yswp-bnmee",
    "x-yswp-bnmee-unthrottled",
    "x-irs-eq",
    "x-irs-dlr",
    "x-irs-bnmee",
    "x-us-cds-eq",
    "x-us-cds-bnmee",
    "x-eu-cds-eq",
    "x-eu-cds-bnmee",
    "x-jgb-eq",
    "x-jgb-dlr",
    "x-jgb-bnmee",
    "x-etf-bnmee",
    "x-etfx-bnmee",
    "x-eeqo-eq",
    "x-eeqo-bnmee",
    "x-tbambs-eq",
    "x-tbambs-dlr",
    "x-mbspool-bnmee",
    "x-eu-cdssn-eq",
    "x-eu-cdssn-bnmee",
    "x-us-cdssn-eq",
    "x-us-cdssn-bnmee",
    "x-agcy-eq",
    "x-agcy-dlr",
    "x-agcy-bnmee",
    "x-can-eq",
    "x-can-dlr",
    "x-fx-refinitiv",
    "x-adn-eq",
    "x-adn-dlr",
    "x-cp-dlr",
    "x-ecp-dlr",
    "x-ui", 
    "x-trsy-staq", 
    "x-ikd-staq",
    "qwe-abc-bnmee",
    "qwe-abc-bnmee-snapshot",
    "ol-ice-ref-price",
    "ol-ice-ref-price-lite",
    "x-rtequity-refinitiv",
    "x-rtequity-refinitiv-test",
    "x-der-eq-bnmee",
    "x-irs-eq-bnmee",
    "x-yswp-eq-bnmee",
    "dev-source-tre-bnm-oms-abc-event",
    "dev-target-tre-bnm-oms-abc-event",
    "dev-bnm-oms-abc-event",
    "us-xpt-dsa-beta-inav-etf",
    "us-xpt-dsa-inav-etf-equities-premium",
    "us-xpt-dsa-inav-etf-equities-standard",
    "us-xpt-dsa-inav-etf-standard",
    "x-sbox-bnm-oms-eucr-session"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=x-ustre.clients.kafka.dev.team.domain.com": [
    "x-ustre-io",
    "x-ustre-bnm",
    "us-xpt-x-pqa-dlr",
    "us-xpt-x-irs-bnmee"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=ol-x-ice-ref-price.clients.kafka.dev.team.domain.com": [
    "ol-ice-ref-price",
    "ol-ice-ref-price-lite"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=tre-bnm.clients.kafka.dev.team.domain.com": [
    "x-ustre-io",
    "tre-all-bnm-prices",
    "tre-filtered-bnm-prices",
    "tre-bnm-intermediate-df-bnm-prices", 
    "tre-bnm-intermediate-df-bnm-session-ranked-post-oc3",
    "us-xpt-tre-bnm-oms-abc-event",
    "us-xpt-tre-bnm-oms-abc-event-session-filtered",
    "us-xpt-stg-bnm-oms-abc-event",
    "us-stg-bnm-oms-abc-event"
  ],
  "OU=team,O=domain,C=US,ST=CJ,CN=non-xpt.docker.x.domain.com": [
    "x-etf-bnm-ne-dsgt-dev",
    "x-etf-bnm-ne-dsgt-demo",
    "x-etf-bnm-ne-dsgt-dlrdev",
    "x-etf-bnm-ne-dsgt-stg",
    "x-etf-bnm-ne-dsgt-stg50",
    "x-ustre-io-snapshot",
    "ol-ice-ref-price",
    "ol-ice-ref-price-lite",
    "x-aery-details"
  ]
}

# Permitted IP addresses that have full Kafka permissions
# Must include brokers.
whitelist_admins := [
  # DEV Jump host
  "/200.200.200.200"
]

#-----------------------------------------------------------------------------
# Helpers for processing Kafka operation input. This logic could be split out
# into a separate file and shared. For conciseness, we have kept it all in one
# place.
#-----------------------------------------------------------------------------
is_topic_resource {
  input.action.resourcePattern.resourceType == "TOPIC"
}

topic_name := input.action.resourcePattern.name {
  is_topic_resource
}

is_idempotent_xptucer {
  input.action.operation == "IDEMPOTENT_WRITE"
  input.action.resourcePattern.resourceType == "CLUSTER"
}

is_xptucer {
  operations := ["WRITE", "DESCRIBE"]
  input.action.operation == operations[_]
  is_topic_resource
}

is_consumer {
  operations := ["READ", "DESCRIBE", "DESCRIBE_CONFIGS"]
  input.action.operation == operations[_]
  is_topic_resource
}

is_consumer_group {
  operations := ["READ", "DESCRIBE"]
  input.action.operation == operations[_]
  input.action.resourcePattern.resourceType == "GROUP"
}
