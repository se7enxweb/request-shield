<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Api\Api;
use CjwNetwork\RequestShield\Api\ApiExtension;
use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Log;
use CjwNetwork\RequestShield\Request;

/**
 * The API's contract (RSF06-05, 0031 G.0): every endpoint every provider
 * declares answers in the schema it declares, and what Api::call() answers
 * in the process is, byte for byte, what HTTP sends (but the second "generated"
 * names). A new endpoint is in here by itself.
 */

/**
 * What does not fit a schema (a JSON Schema subset: type, required, properties, items, enum).
 *
 * @param array<string, mixed> $schema
 * @return list<string>
 */
function contractCheck(mixed $value, array $schema, string $at = 'data'): array
{
    $types = (array) ($schema['type'] ?? []);
    $is = static function (mixed $v, string $t): bool {
        return match ($t) {
            'object' => $v instanceof \stdClass || (is_array($v) && ($v === [] || array_keys($v) !== range(0, count($v) - 1))),
            'array' => is_array($v) && ($v === [] || array_keys($v) === range(0, count($v) - 1)),
            'string' => is_string($v), 'integer' => is_int($v), 'number' => is_int($v) || is_float($v), 'boolean' => is_bool($v), 'null' => $v === null,
            default => false,
        };
    };
    if ($types !== [] && array_filter($types, static fn ($t): bool => $is($value, (string) $t)) === []) {
        return ["$at: not " . implode('|', $types) . ', but ' . get_debug_type($value)];
    }
    if (isset($schema['enum']) && !in_array($value, (array) $schema['enum'], true)) {
        return ["$at: " . json_encode($value) . ' is not one of ' . json_encode($schema['enum'])];
    }
    $out = [];
    $v = $value instanceof \stdClass ? (array) $value : $value;
    if (is_array($v) && $is($value, 'object')) {
        foreach ((array) ($schema['required'] ?? []) as $k) {
            if (!array_key_exists((string) $k, $v)) {
                $out[] = "$at.$k: missing";
            }
        }
        foreach ((array) ($schema['properties'] ?? []) as $k => $sub) {
            if (array_key_exists($k, $v) && is_array($sub)) {
                $out = array_merge($out, contractCheck($v[$k], $sub, "$at.$k"));
            }
        }
    }
    if (is_array($v) && $is($value, 'array') && is_array($schema['items'] ?? null)) {
        foreach ($v as $i => $item) {
            $out = array_merge($out, contractCheck($item, $schema['items'], "{$at}[$i]"));
        }
    }
    return $out;
}

return [
    'RSF06-05 the contract: every endpoint answers in the schema it declares -- the core\'s and the plugins\', reads and writes; a problem is RFC 9457' => function (): void {
        $dir = apiDir();
        try {
            $s = apiSettings($dir, "restrict **/rs/** to 203.0.113.0/24\nset log $dir/shield.log\nset log-level all\nset lists-dir $dir/lists\nset stats on\nset api-write on\n"
                . "ban after 3 refusals in 1m for 10m\n[SITE-OLD] block /old/**\nexpect GET /old/x 404 by SITE-OLD\n");
            Log::write($s, Request::fromServer(['REQUEST_URI' => '/old/x', 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_USER_AGENT' => 'curl/8']),
                Decision::reject(404, 'blocked'), 'SITE-OLD', (float) time(), false);
            $ctx = ['ruleFile' => "$dir/site.rules", 'ip' => '192.0.2.10'];
            $params = [
                'POST /trace' => ['url' => 'https://www.example.org/old/x'],
                'POST /lists' => ['address' => '203.0.113.66', 'note' => 'a test'],
                'GET /log' => ['cursor' => '0:0'],
            ];
            $answered = [];
            foreach (ApiExtension::all() as $ep) {
                $key = "$ep->method $ep->path";
                $p = $params[$key] ?? [];
                if ($key === 'POST /lists/update' || $key === 'POST /lists/remove') {
                    $p = ['id' => Api::call($s, 'GET', '/lists', [], '*', $ctx)['data']['entries'][0]['id'] ?? 'none', 'note' => 'changed'];
                }
                $answer = Api::call($s, $ep->method, $ep->path, $p, '*', $ctx);
                if (!isset($answer['data'])) {
                    same(['type', 'title', 'status', 'detail'], array_keys($answer), "$key: a problem, as RFC 9457");
                    // What may answer a problem here: no ban to lift, no internet for the feeds.
                    truthy(in_array($key, ['POST /lists/lift', 'POST /feeds/update'], true), "$key answered no data: " . json_encode($answer));
                    continue;
                }
                same([], contractCheck($answer['data'], $ep->schema), "$key: in its schema");
                same(['version', 'generated', 'tier'], array_keys($answer['meta']), "$key: meta");
                $answered[] = $key;
            }
            truthy(count($answered) >= 15, 'answered with data: ' . implode(', ', $answered));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-05 the contract: Api::call() in the process and HTTP send the same bytes, for every endpoint that reads; a reader gets the same from both' => function (): void {
        $dir = apiDir();
        try {
            $s = apiSettings($dir, apiTokens() . "set log $dir/shield.log\nset lists-dir $dir/lists\nset stats on\n");
            touch("$dir/shield.log");
            $compared = 0;
            foreach (ApiExtension::all() as $ep) {
                if ($ep->write || $ep->method !== 'GET' || str_starts_with($ep->path, '/openapi')) {
                    continue;
                }
                foreach (['*' => API_ADMIN, 'customer-a' => API_READER] as $who => $token) {
                    if ($who !== '*' && $ep->role !== 'reader') {
                        continue;
                    }
                    $http = json_decode(apiServe($s, 'GET', "/rs/api/v1$ep->path", ['Authorization' => "Bearer $token"])->body, true);
                    $call = json_decode((string) json_encode(Api::call($s, 'GET', $ep->path, [], $who, ['ruleFile' => null])), true);
                    unset($http['meta']['generated'], $call['meta']['generated']);
                    same(json_encode($call), json_encode($http), "GET $ep->path as $who");
                    $compared++;
                }
            }
            truthy($compared >= 10, "compared: $compared");
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
];
