<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

namespace CjwNetwork\RequestShield\Rule;

use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Shield;

/**
 * Addresses on a public blocklist named "deny" (feed …, proposal 0025): 403
 * right after the deny list -- unless the address is let in, a trusted proxy,
 * or a crawler that proved who it is (Shield::feedHit() decides all of that).
 *
 * It holds the shield and calls feedHit() itself, not a closure of it: PHP 8.0's
 * JIT (opcache.jit=1235) crashed calling a \Closure::fromCallable() of that
 * method (JitTest), and a closure of its own costs a call more per request.
 */
final class FeedRule implements Rule
{
    public function __construct(private Shield $shield)
    {
    }

    public function check(Request $request, float $now): ?Decision
    {
        return $this->shield->feedHit($request, 'deny') !== null ? Decision::reject(403, 'feed') : null;
    }

    public function explain(Decision $d, Request $request, Settings $s): ?string
    {
        if ($d->reason !== 'feed') {
            return null;
        }
        $hit = $this->shield->feedHit($request, $d->action === Decision::CHALLENGE ? 'check' : 'deny');
        return is_string($hit) ? $hit : null;
    }
}
