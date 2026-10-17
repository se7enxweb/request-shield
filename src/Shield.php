<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

namespace CjwNetwork\RequestShield;

use CjwNetwork\RequestShield\Challenge\Crawlers;
use CjwNetwork\RequestShield\Challenge\Gate;
use CjwNetwork\RequestShield\Challenge\Secret;
use CjwNetwork\RequestShield\Rule\BanRule;
use CjwNetwork\RequestShield\Rule\BlockedPathRule;
use CjwNetwork\RequestShield\Rule\BudgetRule;
use CjwNetwork\RequestShield\Rule\PostOriginRule;
use CjwNetwork\RequestShield\Rule\CacheableRule;
use CjwNetwork\RequestShield\Rule\ContentRule;
use CjwNetwork\RequestShield\Rule\CrawlerRule;
use CjwNetwork\RequestShield\Rule\DenyRule;
use CjwNetwork\RequestShield\Rule\FeedRule;
use CjwNetwork\RequestShield\Rule\Guarded;
use CjwNetwork\RequestShield\Rule\HostRule;
use CjwNetwork\RequestShield\Rule\LimitsRule;
use CjwNetwork\RequestShield\Rule\MethodPathRule;
use CjwNetwork\RequestShield\Rule\MethodRule;
use CjwNetwork\RequestShield\Rule\PathSanityRule;
use CjwNetwork\RequestShield\Rule\QueryRule;
use CjwNetwork\RequestShield\Rule\RestrictedPathRule;
use CjwNetwork\RequestShield\Rule\Step;
use CjwNetwork\RequestShield\Rule\Rule;
use CjwNetwork\RequestShield\Store\ApcuStore;
use CjwNetwork\RequestShield\Store\FileStore;
use CjwNetwork\RequestShield\Store\MemoryStore;
use CjwNetwork\RequestShield\Store\Store;

/**
 * The request shield: runs before the application and decides whether a
 * request reaches it, and whether its answer may be cached.
 *
 *   CjwNetwork\RequestShield\Shield::protect( require 'request-shield.php' );
 *
 * The checks run cheapest first -- method, sizes, path sanity, host, blocked
 * paths -- and stop at the first rejection, so a scanner's request costs a
 * few string comparisons. The cacheable definition and the budgets follow;
 * a request the budgets want challenged then goes through the gate.
 */
final class Shield
{
    /**
     * The library's version: the next release while on main ("-dev"), the tag
     * once released -- the release job refuses a tag that does not match.
     * BUILD is "source" in the repository; the single-file build (proposal
     * 0002) writes the tag and commit into it.
     */
    public const VERSION = '0.4.0-dev';
    public const BUILD = 'source';

    /** @var list<Rule> */
    private array $rules = [];

    /** @var list<Step>|null the rule chain, derived when asked (chain()) */
    private ?array $steps = null;

    /** @readonly */

    public Settings $settings;

    private Store $store;

    private static ?Decision $current = null;

    private static ?string $rule = null;

    /** The rule file the shield runs from (protectFile()): the dashboard touches it after a change to the lists. */
    private static ?string $ruleFile = null;

    private static ?self $active = null;

    /** The request protect() decided about. */
    private ?Request $request = null;

    /** Whether this request has passed the browser check (a pass, or a solution just now). */
    private bool $passed = false;

    /** Forms larger than this are not carried through the check (the visitor sends them again). */
    private const RESEND_MAX_BYTES = 262144;

    /** What decide() found without the budgets: whether the answer may be cached. */
    private Decision $base;

    /** The max-age of the always-checked path this request is on (challenge … max-age), or null. */
    private ?int $alwaysAge = null;

    /** The rules with those marked "monitor", decided alongside for the log (built when needed). */
    private ?self $watcher = null;

    /**
     * @param array<mixed>|Settings $config see Config::defaults()
     * @param (callable(Request): ?bool)|null $known an adapter's URL index (see CacheableRule)
     * @throws \InvalidArgumentException for a setting of the wrong type
     */
    public function __construct(array|Settings $config = [], ?Store $store = null, ?callable $known = null)
    {
        $s = $this->settings = $config instanceof Settings ? $config : Settings::from($config);
        $this->store = $store ?? self::storeFor($s);
        self::$failedDir = $s->store === 'memory' ? false : $s->storeDir;     // where failed() keeps "already noted"
        $this->base = Decision::allow();
        if ($s->mode === 'off') {
            return;             // no checks at all
        }

        // Kept out (the deny list), then banned for a while: before anything else.
        // The order is Step::table()'s (ChainTest guards it): chain() derives the
        // steps from these rules when a trace or a page asks -- a request never does.
        if ($s->denyTable !== []) {
            $this->rules[] = new DenyRule($s->denyTable);
        }
        if (isset($s->feedTables['deny']) || self::hasAt($s, 'deny')) {
            $this->rules[] = new FeedRule(\Closure::fromCallable([$this, 'feedHit']));
        }
        if ($s->bans !== [] && $s->mode !== 'monitor') {
            if ($s->banKeep === 'file' && $this->store instanceof ApcuStore) {
                self::restoreBans($s, $this->store);
            }
            $this->rules[] = new BanRule($this->store, $s->exemptIps, $s->ipv6Prefix);
        }
        $this->rules[] = new MethodRule($s->methods);
        $this->rules[] = new LimitsRule($s->maxUri, $s->maxQueryParameters, $s->maxHeaderBytes);
        $this->rules[] = new PathSanityRule();
        if ($s->hosts !== []) {
            $this->rules[] = new HostRule($s->hosts);
        }
        $this->rules[] = new BlockedPathRule($s->blockedPaths, $s->blockExceptions, $s->blockedIndex);
        if ($s->methodPaths !== []) {
            $this->rules[] = new MethodPathRule($s->methodPaths);
        }
        // Forms only from the website itself (post-origin same).
        if ($s->postOrigin !== null) {
            $this->rules[] = new PostOriginRule(self::ownNames($s), $s->postOrigin['missing'], $s->postOrigin['except'],
                $s->challenge->apiPaths, $s->exemptIps);
        }
        if ($s->restricted !== []) {
            $this->rules[] = new RestrictedPathRule($s->restricted);
        }
        // Known crawlers the site refuses: only when there are such.
        foreach ($s->crawlers as $x) {
            if ($x['policy'] === 'block') {
                $this->rules[] = new CrawlerRule($this->crawlers());
                break;
            }
        }
        // Known parameters before the attack patterns: cheaper, and they say
        // which values the patterns need to look at.
        if ($s->queryParams !== [] || $s->queryStrict || $s->queryDrop !== []) {
            // set mode monitor watches: nothing is left out of a request then (query drop changes what the application gets).
            $this->rules[] = new QueryRule($s->queryIndex, $s->queryStrict, $s->challenge->widgetPath !== null ? $s->challenge->widgetPath . '/' : null,
                $s->mode === 'monitor' ? [] : $s->queryDrop);
        }
        if ($s->contentIndex !== []) {
            $this->rules[] = new ContentRule($s->contentIndex, $s->contentRules, $s->blockExceptions, $s->contentHints);
        }
        $this->rules[] = new CacheableRule($s->cacheablePaths, $s->cacheableQuery, $known, $s->cacheableIgnore);
        foreach ($s->budgets as $budget) {
            if (!$budget->onDemand) {
                $this->rules[] = $this->budgetRule($budget);
            }
        }
        if (($s->hooks['ruleProvider'] ?? []) !== []) {
            $this->provided($s);                    // the plugins' own rules, after their stage's (0031 C.3)
        }
    }

    /**
     * The rules the plugins with RuleProvider add (0031 C.3): each step after
     * the last step of its stage, never before the lists, its rule behind a
     * guard (a throw says nothing). A provider that throws, or a step at the
     * wrong place, is left out and noted once a minute. Only when a provider
     * is recorded: a shield without one never gets here.
     */
    private function provided(Settings $s): void
    {
        $steps = Step::fromRules($this->rules);
        $core = [];
        foreach ($steps as $st) {
            $core[$st->key] = true;
        }
        foreach ($s->hooks['ruleProvider'] ?? [] as $class) {
            if (!class_exists($class) || !is_subclass_of($class, RuleProvider::class)) {
                continue;
            }
            try {
                $added = (new $class($s))->rules($s, $this->store);
            } catch (\Throwable $e) {
                self::failed('rules', "$class failed to provide its rules, none added: " . $e->getMessage());
                continue;
            }
            foreach ($added as $st) {
                if ($st->rule === null || $st->key === '' || isset($core[$st->key]) || $st->stage === 'lists' || !in_array($st->stage, Step::STAGES, true)) {
                    self::failed('rules', "$class provided a step the chain cannot take (a rule, a key of its own, a stage after the lists) -- left out");
                    continue;
                }
                $core[$st->key] = true;
                $guarded = new Step($st->key, $st->stage, new Guarded($st->rule, $st->key), $st->describe);
                // After the last step of its stage; a stage with no step yet (no budgets): at the end.
                $at = count($steps);
                foreach ($steps as $i => $existing) {
                    if ($existing->stage === $st->stage) {
                        $at = $i + 1;
                    }
                }
                array_splice($steps, $at, 0, [$guarded]);
            }
        }
        // The table must have every core rule (ChainTest guards it); should it not,
        // keep the constructor's list and append the provided rules -- never drop a check.
        $derived = [];
        $own = [];
        foreach ($steps as $st) {
            if ($st->rule !== null) {
                $derived[] = $st->rule;
                if ($st->rule instanceof Guarded) {
                    $own[] = $st->rule;
                }
            }
        }
        if (array_values(array_filter($derived, static fn (Rule $r): bool => !$r instanceof Guarded)) !== $this->rules) {
            self::failed('rules', 'the chain table lags behind the shield: the plugins\' rules run after the core\'s, in the order given');
            $this->steps = null;
            foreach ($own as $rule) {
                $this->rules[] = $rule;
            }
            return;
        }
        $this->steps = $steps;
        $this->rules = $derived;
    }

    /**
     * The first plugin with the Handler capability that answers the request
     * (0031 C.4), or null: on to the application. A handler that throws is
     * noted once a minute and skipped -- the site stays up.
     */
    public function handle(Request $request, Decision $decision): ?Response
    {
        foreach ($this->plugins() as $plugin) {
            if (!$plugin instanceof Handler) {
                continue;
            }
            try {
                $response = $plugin->handle($request, $decision);
            } catch (\Throwable $e) {
                self::failed('handler', get_class($plugin) . ' failed to answer, the application runs: ' . $e->getMessage());
                continue;
            }
            if ($response !== null) {
                return $response;
            }
        }
        return null;
    }

    /**
     * The first plugin with the MethodHandler capability that answers a
     * request with a method the site does not take (0031 G.4), or null: the
     * rules decide. One that throws is noted once a minute and skipped.
     */
    public function handleMethod(Request $request): ?Response
    {
        foreach ($this->plugins() as $plugin) {
            if (!$plugin instanceof MethodHandler) {
                continue;
            }
            try {
                $response = $plugin->handleMethod($request);
            } catch (\Throwable $e) {
                self::failed('handler', get_class($plugin) . ' failed to answer ' . $request->method . ', the rules decide: ' . $e->getMessage());
                continue;
            }
            if ($response !== null) {
                return $response;
            }
        }
        return null;
    }

    /**
     * The application says who the visitor is (0031 G.4, proposal 0039):
     * Shield::active()?->cacheContext($roleKey) from an adapter while the
     * application runs. The plugins with the ContextHandler capability (the
     * HTTP cache) remember it for the session the request carries and, with
     * $shared, may keep this answer for everyone with the role. Nothing
     * happens without such a plugin, or before protect() ran; one that throws
     * is noted once a minute -- the application goes on.
     */
    public function cacheContext(string $context, bool $shared = false): void
    {
        $this->toContext(static function (ContextHandler $p, Request $r) use ($context, $shared): void {
            $p->cacheContext($r, $context, $shared);
        });
    }

    /** The visitor signed out: their session's role is forgotten (the logout hook of an adapter). */
    public function forgetContext(): void
    {
        $this->toContext(static function (ContextHandler $p, Request $r): void {
            $p->forgetContext($r);
        });
    }

    /**
     * The query as the caches and the application get it (0048): the
     * parameters cache-ignore names leave $_GET, $_REQUEST, QUERY_STRING and
     * REQUEST_URI (a copy as JSON in REQUEST_SHIELD_IGNORED: name => value);
     * with cache-unknown-query hit-only and a parameter cache-query does not
     * name, REQUEST_SHIELD_CACHE_LOOKUP is the address (path and the
     * cache-query parameters, sorted) a cache may answer from. Returns the
     * request as it is now.
     */
    private static function queryForCaches(Settings $s, Request $request, Decision $decision): Request
    {
        $kept = [];
        $gone = [];
        $dropped = $request->dropped();
        // What leaves, by the name PHP gives it in $_GET: a name cache-query names stays in the key, whatever a
        // glob of cache-ignore matches (p* and page); one query drop left out goes whatever cache-query says
        // (page=2' is no page).
        $goes = [];
        foreach ($request->queryPairs() as [$name, , $raw]) {
            if (isset($dropped[$name]) || (!in_array($name, (array) $s->cacheableQuery, true) && \CjwNetwork\RequestShield\Rule\CacheableRule::ignored($name, $s->cacheableIgnore))) {
                $goes[Request::phpKey($raw)] = true;
            }
        }
        // ... and every pair PHP puts under that key goes with it (" page", "items[per[page" are $_GET['page'],
        // $_GET['items_per_page']): what the application reads, the query and the cache key stay one and the same.
        foreach ($request->queryPairs() as [$name, $value, $raw]) {
            $key = Request::phpKey($raw);
            if (isset($goes[$key])) {
                $gone[$key] = $value;
            } else {
                $kept[] = [$name, $raw];
            }
        }
        $uri = is_string($_SERVER['REQUEST_URI'] ?? null) ? $_SERVER['REQUEST_URI'] : $request->rawUri;
        $path = (string) strtok($uri, '?');
        if ($gone !== []) {
            $query = implode('&', array_column($kept, 1));
            $_SERVER['QUERY_STRING'] = $query;
            $_SERVER['REQUEST_URI'] = $path . ($query === '' ? '' : '?' . $query);
            $_SERVER['REQUEST_SHIELD_IGNORED'] = (string) json_encode($gone, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            // $_GET is what PHP's own parser makes of the query that is left -- not the old one with names
            // taken out: whatever PHP does with a name (folds it, drops it, lets a too deep one remove another),
            // the application reads exactly the query the cache key is made of.
            parse_str($query, $get);
            $_GET = $get;
            // $_REQUEST as PHP makes it: the sources request_order names, the later winning -- arrays merged.
            $merged = [];
            foreach (str_split(strtoupper((string) (ini_get('request_order') ?: ini_get('variables_order')))) as $source) {
                $merged = self::mergeInput($merged, $source === 'G' ? $_GET : ($source === 'P' ? $_POST : ($source === 'C' ? $_COOKIE : [])));
            }
            $_REQUEST = $merged;
            /** @var array<string, mixed> $server */
            $server = $_SERVER;
            $request = Request::fromServer($server, $s->trustedProxies);
        }
        if ($s->cacheableUnknown === 'hit-only' && $s->cacheableQuery !== null && !$decision->cacheable() && $decision->reason === 'query parameter') {
            $key = array_values(array_filter($kept, static fn (array $p): bool => in_array($p[0], (array) $s->cacheableQuery, true)));
            $pairs = array_column($key, 1);
            sort($pairs, SORT_STRING);
            $_SERVER['REQUEST_SHIELD_CACHE_LOOKUP'] = $path . ($pairs === [] ? '' : '?' . implode('&', $pairs));
        }
        return $request;
    }

    /**
     * Two input arrays as PHP merges them into $_REQUEST: the later wins, an
     * array under the same name in both is merged the same way (?a[x]=1 and a
     * cookie a[y]=2 are a = [x => 1, y => 2]).
     *
     * @param array<mixed> $into
     * @param array<mixed> $from
     * @return array<mixed>
     */
    private static function mergeInput(array $into, array $from): array
    {
        foreach ($from as $k => $v) {
            $into[$k] = is_array($v) && is_array($into[$k] ?? null) ? self::mergeInput($into[$k], $v) : $v;
        }
        return $into;
    }

    /**
     * The application changed content (0031 G.5, proposal 0039):
     * Shield::active()?->purge(['content-12', 'list']) from an adapter when
     * a page is published -- the plugins with the Purger capability (the
     * HTTP cache) make the answers with these tags out of date ("*":
     * everything), with no PURGE request. Nothing happens without such a
     * plugin; one that throws is noted once a minute -- the application goes
     * on.
     *
     * @param list<string> $tags
     */
    public function purge(array $tags): void
    {
        if ($tags === [] || ($this->settings->hooks['purger'] ?? []) === []) {
            return;
        }
        foreach ($this->plugins() as $plugin) {
            if (!$plugin instanceof Purger) {
                continue;
            }
            try {
                $plugin->purge($tags);
            } catch (\Throwable $e) {
                self::failed('handler', get_class($plugin) . ' failed to purge, the application goes on: ' . $e->getMessage());
            }
        }
    }

    /** @param \Closure(ContextHandler, Request): void $call */
    private function toContext(\Closure $call): void
    {
        $request = $this->request;
        if ($request === null || ($this->settings->hooks['contextHandler'] ?? []) === []) {
            return;
        }
        foreach ($this->plugins() as $plugin) {
            if (!$plugin instanceof ContextHandler) {
                continue;
            }
            try {
                $call($plugin, $request);
            } catch (\Throwable $e) {
                self::failed('handler', get_class($plugin) . ' failed to take the visitor\'s role, the application goes on: ' . $e->getMessage());
            }
        }
    }

    /**
     * The rule chain (0031 C.1): every step in the order the shield checks,
     * the stages' steps without a rule where their settings are not in use.
     * Derived from the rules when first asked (a trace, the rules page) --
     * a request pays nothing for it.
     *
     * @return list<Step>
     */
    public function chain(): array
    {
        return $this->steps ??= $this->settings->mode === 'off' ? [] : Step::fromRules($this->rules);
    }

    /**
     * The rules the request path runs, in order (the active steps of chain()).
     *
     * @return list<Rule>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    /**
     * protect() with the settings of a file, checked only when it changed
     * (see Settings::load()): the way to run the shield on every request.
     * A ".rules" file is a rule file; $sources are further rule files or
     * globs read before it -- an adapter's, for its extensions.
     *
     * @param (callable(Request): ?bool)|null $known
     * @param list<string> $sources
     */
    public static function protectFile(string $file, ?callable $known = null, ?string $cacheDir = null, array $sources = []): Decision
    {
        // Where "already noted" is kept before any settings exist: with the compiled ones.
        self::$failedDir ??= $cacheDir ?? Settings::cacheDirFor($file);
        self::$ruleFile = $file;
        try {
            // With site blocks (rules per website): the settings of this request's website.
            $settings = Settings::loadFor($file, $_SERVER, $cacheDir, $sources);
        } catch (\Throwable $e) {
            return self::failedOpen($e, null);      // the settings cannot be had: the site stays up (ADR 0007)
        }
        return self::protect($settings, $known);
    }

    /**
     * The shield failed: the request goes on to the application, never
     * cached, and the error log gets one line a minute. What the application
     * sees is the same as for any uncached pass.
     */
    private static function failedOpen(\Throwable $e, ?Settings $s): Decision
    {
        $d = Decision::allowUncached('shield error');
        self::$current = $d;
        self::$rule = null;
        $_SERVER['REQUEST_SHIELD'] = $d->action;
        self::failed('shield', 'the shield failed and let the request through: ' . get_class($e) . ': ' . $e->getMessage()
            . ' in ' . $e->getFile() . ':' . $e->getLine());
        if ($s !== null && $s->debugHeader && !headers_sent()) {
            header('X-RS: ' . $d->action . ' ' . $d->reason);
        }
        return $d;
    }

    /**
     * Decides about the request in $_SERVER, answers it itself when the
     * application must not run (and ends the request), and returns the
     * decision otherwise. Also Shield::current() and
     * $_SERVER['REQUEST_SHIELD'] ("allow" or "allow-uncached") afterwards.
     *
     * An array is checked on every call; protectFile() checks it once.
     *
     * @param array<mixed>|Settings $config
     * @param (callable(Request): ?bool)|null $known
     */
    public static function protect(array|Settings $config = [], ?callable $known = null): Decision
    {
        // Fail safe (ADR 0007): whatever breaks inside the shield, the request
        // reaches the application -- uncached -- and PHP's error log hears it
        // once a minute. exit() is not a Throwable: the shield's own answers
        // (a refusal, the check page) are not affected.
        try {
            return self::run($config, $known);
        } catch (\Throwable $e) {
            return self::failedOpen($e, $config instanceof Settings ? $config : null);
        }
    }

    /**
     * What protect() does; apart.
     *
     * @param array<mixed>|Settings $config
     * @param (callable(Request): ?bool)|null $known
     */
    private static function run(array|Settings $config, ?callable $known): Decision
    {
        $shield = new self($config, null, $known);
        $s = $shield->settings;
        /** @var array<string, mixed> $server */
        $server = $_SERVER;
        $request = Request::fromServer($server, $s->trustedProxies);
        $shield->request = $request;
        self::$active = $shield;
        if ($s->mode === 'off') {
            // Switched off: nothing checked, counted or logged; the include stays.
            self::$current = Decision::allow();
            self::$rule = null;
            $_SERVER['REQUEST_SHIELD'] = Decision::ALLOW;
            return self::$current;
        }
        // A method the site does not take, answered by a plugin before the rules (MethodHandler,
        // 0031 G.4): an HTTP cache's PURGE from its purgers -- for a GET, one array access.
        if (($s->hooks['methodHandler'] ?? []) !== [] && !in_array($request->method, $s->methods, true)) {
            $response = $shield->handleMethod($request);
            if ($response !== null) {
                $response->send();
                exit;
            }
        }
        $now = microtime(true);
        $decided = $shield->decide($request, $now);
        // The endpoint of the check inside the form: answered here, before the
        // application -- after the checks, so budgets count it and a refused
        // client stays refused; a challenged one gets its task (that is what
        // it asks for).
        $w = $s->challenge->widgetPath;
        if ($w !== null && strncmp($request->path, $w . '/', strlen($w) + 1) === 0
            && ($decided->passes() || $decided->action === Decision::CHALLENGE)) {
            $shield->serveWidget(substr($request->path, strlen($w) + 1), $request, $now);
            exit;
        }
        $settled = $shield->settle($decided, $request, $now);
        $decision = $settled['decision'];
        $shield->passed = $settled['passed'];
        if (!$decision->passes() && ($s->bans !== [] || ($s->monitor !== null && $s->monitor->bans !== []))) {
            $shield->signals($decision, $request, $now);         // what may lead to a ban: only when refused, slowed or checked
        }
        // Which rule: looked up only for a request that was stopped or flagged
        // (or when every request is logged) -- a passing one costs nothing.
        $rule = null;
        $watched = null;
        $would = null;
        $reference = null;
        if ($s->mode === 'monitor' && !$decision->passes()) {
            $would = $decision;
            // Monitor: decided and counted, logged as it would be -- and let through,
            // never cached (whatever it is, it is not what a cache should keep).
            $watched = $shield->watched($decision, $request, $now, $shield);
            $decision = Decision::allowUncached('monitor');
            $settled = ['decision' => $decision, 'cookies' => $settled['cookies'], 'page' => null, 'json' => null, 'passed' => false];
        } elseif ($decision->action !== Decision::ALLOW || $s->logLevel === 'all') {
            $rule = $shield->explain($decision, $request);
            // A refusal the shield answers with its page (not the check page): a reference
            // on the page and in the log line (0030) -- made only then.
            $reference = !$decision->passes() && $settled['page'] === null && ($settled['json'] ?? null) === null ? ErrorPage::reference() : null;
            Log::note($s, $request, $decision, $rule, $now, false, $reference);
        }
        if ($s->monitor !== null && $decision->passes() && $watched === null) {
            // Rules marked "monitor": what they would decide, for the log.
            $watched = $shield->watch($request, $now);
        }
        self::$current = $decision;
        self::$rule = $rule;
        if ($s->learn !== null) {
            try {
                Learn::note($s, $request, $decision, $now);    // a learning run (0016): only its own requests, their shape
            } catch (\Throwable $e) {
                // A recording's trouble never turns a decision around: noted (once a minute), the request goes on.
                Failure::note('learn', $e->getMessage(), $s->storeDir);
            }
        }
        if ($shield->plugins() !== []) {
            // The plugins (the statistics, …): told now, and -- for a request that
            // goes on to the site -- again when it has ended, with the site's status.
            $shield->record($request, $decision, $rule, $now, $would, $decision->passes());
        }
        if (!headers_sent()) {
            foreach ($settled['cookies'] as $cookie) {
                header('Set-Cookie: ' . $cookie, false);
            }
        }

        if (!$request->viaTrustedProxy && $s->stripUntrustedForwarded) {
            foreach (array_keys($_SERVER) as $name) {
                if (is_string($name) && strncmp($name, 'HTTP_X_FORWARDED_', 17) === 0) {
                    unset($_SERVER[$name]);
                }
            }
            unset($_SERVER['HTTP_FORWARDED']);
        }

        if (!$decision->passes() && ($settled['json'] ?? null) !== null) {
            echo (new Responder())->api($decision, $settled['json'], $s->debugHeader, $rule);
            exit;
        }
        if (!$decision->passes()) {
            $c = $s->challenge;
            (new Responder())->send($decision, $request, $s->debugHeader, $settled['page'], $rule,
                Texts::all(Texts::language($c->language, $request->header('accept-language'), $c->texts), $c->texts), $c->home, PageHook::asker($s),
                $c->logo, $settled['page'] === null && $shield->isApi($request), $reference, $s->errorPages);
            exit;
        }
        // The dashboard's own pages (0031 B.6): a route is answered here, before the
        // application -- for the many requests that are none, one stripos.
        $route = Dashboard::routeFor($s, $request);
        if ($route !== null) {
            /** @var array<mixed> $get */
            $get = $_GET;
            /** @var array<mixed> $post */
            $post = $_POST;
            Dashboard::serve($s, $request, $route, $get, $post, self::$ruleFile)->send();
            exit;
        }
        // The query for the caches (0048): decided, logged and counted on the whole query above;
        // the parameters no cache key holds leave it now, before a cache and the application run.
        if (($s->cacheableIgnore !== [] || $s->cacheableUnknown !== 'uncached' || ($s->queryDrop !== [] && $request->dropped() !== [])) && ($request->method === 'GET' || $request->method === 'HEAD')) {
            $request = self::queryForCaches($s, $request, $decision);
        }
        // A plugin that answers passing requests itself (Handler, 0031 C.4): an HTTP
        // cache hit, a page of its own -- one array access when none has it.
        if (($s->hooks['handler'] ?? []) !== []) {
            $response = $shield->handle($request, $decision);
            if ($response !== null) {
                $_SERVER['REQUEST_SHIELD'] = $decision->action;
                if ($s->debugHeader && !headers_sent()) {
                    header(self::serverTiming($now));       // the shield and the plugin that answered (a cache hit)
                }
                $response->send();
                exit;
            }
        }
        if ($s->appChallenge && ($request->method === 'GET' || $request->method === 'HEAD')) {
            $shield->watchForChallengeHeader();
        }
        $_SERVER['REQUEST_SHIELD'] = $decision->action;
        if ($rule !== null) {
            $_SERVER['REQUEST_SHIELD_RULE'] = $rule;
        }
        if ($s->debugHeader && !headers_sent()) {
            header(self::serverTiming($now));
            header('X-RS: ' . ($watched !== null && $s->mode === 'monitor' ? 'monitor ' . $watched
                : $decision->action . ($decision->reason !== '' ? ' ' . $decision->reason : '') . ($rule !== null ? '; rule=' . $rule : '')));
            if ($watched !== null && $s->mode !== 'monitor') {
                header('X-RS-Monitor: ' . $watched);
            }
        }
        return $decision;
    }

    /**
     * The shield's own time for the browser's network tab (0046 step 3), with
     * debug-header on only: from its decision's start to here, in
     * milliseconds -- "Server-Timing: shield;dur=0.042;desc=request-shield".
     * The site's time is not over when the headers go out; for every visitor
     * it would tell that a shield is in front and cost bytes on every answer.
     */
    private static function serverTiming(float $start): string
    {
        return 'Server-Timing: shield;dur=' . number_format(max(0.0, microtime(true) - $start) * 1000, 3, '.', '') . ';desc=request-shield';
    }

    /**
     * What the rules marked "monitor" would decide about a request the
     * enforced rules let through: logged, never acted on. Returns it in
     * words ("reject blocked path; rule=SITE-OLD") or null when they would
     * let it through too.
     */
    private function watch(Request $request, float $now): ?string
    {
        $w = $this->watcher($request);
        if ($w === null) {
            return null;
        }
        $d = $w->decide($request, $now);
        if ($d->passes()) {
            return null;
        }
        // A check the visitor has passed already (a pass cookie) is no refusal.
        $d = $w->settle($d, $request, $now)['decision'];
        return $d->passes() ? null : $this->watched($d, $request, $now, $w);
    }

    /**
     * Tells the plugins what was decided (the statistics: counted for the
     * dashboard, a crawler's log -- see StatsPlugin). protect() calls it; code
     * that runs decide() and settle() itself calls it after them. Without a
     * plugin it costs nothing.
     *
     * @param Decision|null $would what monitor mode would have done
     * @param bool $atEnd the request goes on to the site: the plugins hear
     *   again when it ends, with the status the site answered
     */
    public function record(Request $request, Decision $decision, ?string $rule, float $now, ?Decision $would = null, bool $atEnd = false): void
    {
        $plugins = $this->plugins();
        if ($plugins === []) {
            return;
        }
        $seen = new Seen($request, $this);
        foreach ($plugins as $plugin) {
            try {
                $plugin->decided($request, $decision, $rule, $seen, $now, $atEnd, $would);
            } catch (\Throwable $e) {
                self::pluginFailed($plugin, $e);
            }
        }
        if (!$atEnd) {
            return;
        }
        // The site answers: when it is done, the plugins hear its status.
        register_shutdown_function(static function () use ($plugins, $request, $seen, $now): void {
            $status = http_response_code();
            $headers = headers_list();
            foreach ($plugins as $plugin) {
                try {
                    $plugin->ended($request, is_int($status) && $status > 0 ? $status : 0, $headers, $seen, $now);
                } catch (\Throwable $e) {
                    self::pluginFailed($plugin, $e);
                }
            }
        });
    }

    /**
     * The website's own names, for post-origin: the host rule's, and in a site
     * block that block's names ("default" is none); [] when there are none --
     * then the name the request was sent to.
     *
     * @return list<string>
     */
    public static function ownNames(Settings $s): array
    {
        $names = $s->hosts;
        if ($s->site !== null) {
            foreach ($s->sites as $name => $block) {
                if ($block === $s->site && $name !== 'default') {
                    $names[] = $name;
                }
            }
        }
        return array_values(array_unique(array_map('strtolower', $names)));
    }

    /**
     * The signals a decision gives for the bans: past a limit (a pause, a spent
     * check), a refusal for what only attackers ask for, a check page shown.
     * protect() gives them after settling a request that did not pass;
     * request-shield test does the same, so an example can reach a ban.
     */
    public function signals(Decision $d, Request $request, float $now): void
    {
        if ($d->action === Decision::THROTTLE && $d->reason !== 'banned') {
            $this->signal('limits', $request, $now);
        } elseif ($d->action === Decision::CHALLENGE) {
            $this->signal('checks', $request, $now);
            if ($d->spent) {
                $this->signal('limits', $request, $now);
            }
        } elseif ($d->action === Decision::REJECT && ($d->reason === 'blocked path' || $d->reason === 'attack')) {
            $this->signal('refusals', $request, $now);
        }
    }

    /** One signal: counted for every ban that names it; past its number, the ban (or, watched, a line in the log). */
    private function signal(string $name, Request $request, float $now): void
    {
        $s = $this->settings;
        $enforced = $s->mode === 'monitor' ? [] : $s->bans;
        $rules = array_column($enforced, 'rule');
        // Watched: every ban in monitor mode, and those marked "monitor ban".
        $watched = $s->mode === 'monitor' ? $s->bans : [];
        foreach ($s->monitor !== null ? $s->monitor->bans : [] as $b) {
            if (!in_array($b['rule'], $rules, true) && !in_array($b, $watched, true)) {
                $watched[] = $b;
            }
        }
        foreach ([[$enforced, false], [$watched, true]] as [$bans, $watch]) {
            foreach ($bans as $b) {
                if ($b['signal'] === $name) {
                    $this->countBan($b, $request, $now, $watch);
                }
            }
        }
    }

    /**
     * A signal for one ban: past its number in its window, the client is
     * banned -- longer each time within a day (ban-growth), at most ban-max.
     * Never an address let in (exempt), a trusted proxy or a verified crawler.
     *
     * @param array{after: int, signal: string, in: int, for: int, rule: string} $b
     */
    private function countBan(array $b, Request $request, float $now, bool $watch): void
    {
        $s = $this->settings;
        $ip = $request->clientIp;
        if (IpAddress::inRanges($ip, $s->exemptIps) || IpAddress::inRanges($ip, $s->trustedProxies)) {
            return;
        }
        $bucket = IpAddress::bucket($ip, $s->ipv6Prefix);
        // On a public blocklist named "ban-signal <n>": one signal counts n times.
        $weight = 1;
        if ($s->feedWeights !== [] && ($feed = $this->feedHit($request, 'signal')) !== null) {
            $weight = $s->feedWeights[$feed] ?? 1;
        }
        $count = 0.0;
        for ($i = 0; $i < $weight; $i++) {
            $count = $this->store->hit(($watch ? 'monitor:' : '') . 'ban:' . $b['rule'] . ':' . $bucket, $b['in'], $now);
        }
        if ($count < $b['after']) {
            return;
        }
        $id = $s->crawlers === [] ? null : $this->crawlers()->claims((string) $request->header('user-agent'));
        if ($id !== null && $this->crawlers()->verified($ip, $id)) {
            return;                                         // a verified crawler gets the pause it understands, never a ban
        }
        if ($watch) {
            Log::note($s, $request, Decision::throttle('banned', $b['for']), $b['rule'], $now, true);
            return;
        }
        $offences = (int) round($this->store->hit('bans:' . $bucket, 86400, $now));
        $duration = (int) min($s->banMax, $b['for'] * $s->banGrowth ** max(0, min($offences - 1, 30)));
        $until = (int) $now + $duration;
        if ($this->store->marked('ban:' . $bucket, $now) >= $until) {
            return;                                         // banned longer already
        }
        $this->store->mark('ban:' . $bucket, $until, $now);
        if ($s->banKeep === 'file' && !$this->store instanceof FileStore) {
            (new FileStore($s->storeDir))->mark('ban:' . $bucket, $until, $now);     // survives a restart of APCu
        }
        Log::note($s, $request, Decision::throttle('banned', $duration), $b['rule'], $now);
    }

    /**
     * set ban-keep file: after a restart of APCu (empty), the first request
     * copies the bans still running from their files back -- once: apcu_add()
     * lets one process do it. Every other request: that one call.
     */
    private static function restoreBans(Settings $s, Store $store): void
    {
        if (!Capability::apcu() || !apcu_add('rshield-bans-restored:' . hash('crc32b', $s->storeDir), 1)) {
            return;
        }
        $now = microtime(true);
        foreach ((new FileStore($s->storeDir))->marks('ban:', $now) as $key => $until) {
            if ($store->marked($key, $now) < $until) {
                $store->mark($key, $until, $now);
            }
        }
    }

    /**
     * Lifts a ban at once, wherever it is kept: the store and, with
     * ban-keep file, its file. False when the address is not banned.
     */
    public static function liftBan(Settings $s, Store $store, string $bucket, ?float $now = null): bool
    {
        $now ??= microtime(true);
        $key = 'ban:' . $bucket;
        $was = $store->marked($key, $now) > 0;
        $store->mark($key, 0, $now);
        if ($s->banKeep === 'file' && !$store instanceof FileStore) {
            $file = new FileStore($s->storeDir);
            $was = $was || $file->marked($key, $now) > 0;
            $file->mark($key, 0, $now);
        }
        return $was;
    }

    /** @var list<Plugin>|null */
    private ?array $plugins = null;

    /**
     * The plugins of these settings, made once: those the rules name ("plugin
     * …") and those the extensions added when the rules were compiled (the
     * statistics with "set stats" or "set crawler-log": StatsExtension::plugins()).
     * A class that is missing or no Plugin is left out (and logged).
     *
     * @return list<Plugin>
     */
    public function plugins(): array
    {
        if ($this->plugins !== null) {
            return $this->plugins;
        }
        $s = $this->settings;
        $made = [];
        foreach ($s->plugins as $class) {
            try {
                if (!class_exists($class) && isset($s->pluginFiles[$class]) && is_file($s->pluginFiles[$class])) {
                    require_once $s->pluginFiles[$class];   // plugin … from <file> (0031 D.2): only here, only with plugins
                }
                $plugin = class_exists($class) && is_subclass_of($class, Plugin::class) ? new $class($s) : null;
            } catch (\Throwable $e) {
                $plugin = null;
            }
            if ($plugin instanceof Plugin) {
                $made[] = $plugin;
            } else {
                self::pluginFailed($class, null);
            }
        }
        return $this->plugins = $made;
    }

    /**
     * Where failed() keeps "already noted" across requests and workers: the
     * site's store directory; null before any settings were made (the
     * temp dir then); false with the memory store (nothing persists: in
     * this process only -- the tests' case).
     */
    private static string|false|null $failedDir = null;

    /** Something failed and the request went on: noted once a minute per cause (Failure). */
    public static function failed(string $what, string $message): void
    {
        Failure::note($what, $message, self::$failedDir);
    }

    /** A plugin that failed. */
    private static function pluginFailed(Plugin|string $plugin, ?\Throwable $e): void
    {
        $name = is_string($plugin) ? $plugin : get_class($plugin);
        self::failed($name, 'plugin ' . (is_string($plugin) ? $plugin . ' is missing or no ' . Plugin::class : get_class($plugin) . ' failed: ' . ($e !== null ? $e->getMessage() : '?')));
    }

    /** The shield of the rules marked "monitor" (null: there are none), built once. */
    private function watcher(Request $request): ?self
    {
        $m = $this->settings->monitor;
        if ($m === null) {
            return null;
        }
        if ($this->watcher === null) {
            // Their own budgets are counted; those the enforced rules have, only looked at.
            $own = array_fill_keys(array_keys(array_diff_key($m->budgets, $this->settings->budgets)), true);
            $this->watcher = new self($m, new \CjwNetwork\RequestShield\Store\MonitorStore($this->store, $own));
            $this->watcher->request = $request;
        }
        return $this->watcher;
    }

    /** Logs what would have been decided ("monitor-reject …") and returns it in words for the header. */
    private function watched(Decision $d, Request $request, float $now, self $by): string
    {
        $s = $this->settings;
        $rule = $by->explain($d, $request);
        Log::note($s, $request, $d, $rule, $now, true);
        return $d->action . ($d->reason !== '' ? ' ' . $d->reason : '') . ($rule !== null ? '; rule=' . $rule : '');
    }

    /** The decision protect() made for this request, if it ran. */
    public static function current(): ?Decision
    {
        return self::$current;
    }

    /**
     * The shield protect() ran with, to count on-demand budgets against the
     * same settings and request: Shield::active()?->consume('searches').
     */
    public static function active(): ?self
    {
        return self::$active;
    }

    /** The rule behind current(), when it was not a plain "allow" (see explain()). */
    public static function currentRule(): ?string
    {
        return self::$rule;
    }

    /**
     * The rule behind a decision, as the log and the pages name it: asked from
     * the chain's rules (Rule::explain(), 0031 C.2); what no rule produces --
     * the always-checked paths, a "check" feed, the application's own check --
     * is named here.
     */
    public function explain(Decision $d, Request $request): ?string
    {
        $s = $this->settings;
        switch ($d->reason) {
            case 'app':
                return 'application';
            case 'always':
                foreach ($s->challenge->alwaysPaths as $i => $p) {
                    if (@preg_match($p, $request->path) === 1 && $s->challenge->alwaysFor($p, $request->method)) {
                        return $s->ruleName('challenge.alwaysPaths', $s->challenge->alwaysPaths[$i], "challenge.alwaysPaths[$i]");
                    }
                }
                return null;
        }
        foreach ($this->rules as $rule) {
            $name = $rule->explain($d, $request, $s);
            if ($name !== null) {
                return $name;
            }
        }
        // A "check" feed is decide()'s own step after the chain (the deny feeds are FeedRule's).
        if ($d->reason === 'feed') {
            return $this->feedHit($request, $d->action === Decision::CHALLENGE ? 'check' : 'deny');
        }
        // A budget the site counts itself (on-demand, consume()): no step of the chain.
        if (isset($s->budgets[$d->reason])) {
            return $s->ruleName('budgets', $d->reason, "budgets.$d->reason");
        }
        return null;
    }

    public function decide(Request $request, float $now): Decision
    {
        $base = Decision::allow();
        $budget = null;
        $this->alwaysAge = null;
        // The dashboard's own pages, opened from an address their restrict rule
        // allows: not counted against the pace (the live view asks every few seconds).
        $ownPage = $this->settings->restricted !== [] && $this->dashboardOnly($request);
        foreach ($this->rules as $rule) {
            if ($ownPage && $rule instanceof BudgetRule) {
                continue;
            }
            // strict: a request a cache must not keep counts twice -- the pattern
            // of floods that bust the cache with made-up addresses.
            $wants = $rule instanceof BudgetRule
                ? $rule->check($request, $now, $base->action === Decision::ALLOW_UNCACHED ? $this->settings->uncachedWeight : 1)
                : $rule->check($request, $now);
            if ($wants === null) {
                continue;
            }
            if ($wants->action === Decision::REJECT || $rule instanceof BanRule) {
                return $this->base = $wants;            // a banned client: one lookup, and the answer
            }
            if ($rule instanceof BudgetRule || ($rule instanceof PostOriginRule && $wants->action === Decision::CHALLENGE)) {
                // A check -- a budget's, or a form without Origin and Referer -- goes through the gate.
                $budget = $budget === null ? $wants : $budget->stricter($wants);
            } else {
                $base = $base->stricter($wants);
            }
        }
        $this->base = $base;
        // Paths that are always checked (a login page): challenged whatever the
        // budgets say, every method -- a bot must not POST to a login without
        // having loaded it -- or only the methods the rule names (challenge POST
        // **: every form sent, not the pages that show them). The gate lets a
        // client with a pass cookie through; a form without one gets the page,
        // which sends it again once the check is done.
        $always = $this->settings->challenge->alwaysPaths;
        // An address let in (exempt, the allow list) never meets the check.
        if ($always !== [] && !($this->settings->exemptIps !== [] && IpAddress::inRanges($request->clientIp, $this->settings->exemptIps))) {
            foreach ($always as $pattern) {
                if (@preg_match($pattern, $request->path) === 1 && $this->settings->challenge->alwaysFor($pattern, $request->method)) {
                    $budget = $budget === null ? Decision::challenge('always') : $budget->stricter(Decision::challenge('always'));
                    $this->alwaysAge = $this->settings->challenge->alwaysMaxAge[$pattern] ?? null;
                    break;
                }
            }
        }
        // On a public blocklist named "check": the browser check, as on an
        // always-checked page -- a pass lets the visitor through.
        if ((isset($this->settings->feedTables['check']) || self::hasAt($this->settings, 'check')) && $this->feedHit($request, 'check') !== null) {
            $budget = $budget === null ? Decision::challenge('feed') : $budget->stricter(Decision::challenge('feed'));
        }
        return $budget === null ? $base : $base->stricter($budget);
    }

    /**
     * Whether a request is for one of the dashboard's pages (the compiled
     * routes: /rs/waf/live, /rs/stats/visitors … -- also below a prefix,
     * /demo/rs/waf/live) from an address the restrict rule over that path
     * allows. Without such a rule the pages count like any other: an open
     * dashboard keeps its flood guard. Only called with restrict rules in
     * force; the routes are a handful of string comparisons.
     */
    private function dashboardOnly(Request $request): bool
    {
        $s = $this->settings;
        $path = $request->matchPath();
        if (Routes::match($s, $path) === null) {
            return false;                                   // the common case: a search or two
        }
        foreach ($s->restricted as $r) {
            foreach ($r['paths'] as $pattern) {
                if (@preg_match($pattern, $path) === 1) {
                    return IpAddress::inRanges($request->clientIp, $r['ips']);
                }
            }
        }
        return false;
    }

    /** @var array<string, ?string> client|action => the rule found, this request */
    private array $feedHits = [];

    /**
     * The rule of the public blocklist that holds this client for an action
     * (deny, check, signal) -- null when none does, or when the client is let
     * in, a trusted proxy, or a crawler that proved who it is.
     */
    public function feedHit(Request $request, string $action): ?string
    {
        $key = $request->clientIp . '|' . $action . '|' . $request->path;
        if (array_key_exists($key, $this->feedHits)) {
            return $this->feedHits[$key];
        }
        $s = $this->settings;
        $rule = isset($s->feedTables[$action]) ? IpTable::find($request->clientIp, $s->feedTables[$action]) : null;
        foreach ($rule === null ? $s->feedsAt : [] as $f) {
            if ($f['action'] !== $action || ($id = IpTable::find($request->clientIp, $f['table'])) === null) {
                continue;
            }
            foreach ($f['paths'] as $p) {
                if (@preg_match($p, $request->path) === 1) {
                    $rule = $id;
                    break 2;
                }
            }
        }
        if ($rule !== null && (IpAddress::inRanges($request->clientIp, $s->exemptIps) || IpAddress::inRanges($request->clientIp, $s->trustedProxies))) {
            $rule = null;
        }
        if ($rule !== null && $s->crawlers !== []) {
            $id = $this->crawlers()->claims((string) $request->header('user-agent'));
            if ($id !== null && $this->crawlers()->verified($request->clientIp, $id)) {
                $rule = null;                               // a crawler that proved who it is: never by a list
            }
        }
        if (count($this->feedHits) > 64) {
            $this->feedHits = [];
        }
        return $this->feedHits[$key] = $rule;
    }

    private static function hasAt(Settings $s, string $action): bool
    {
        foreach ($s->feedsAt as $f) {
            if ($f['action'] === $action) {
                return true;
            }
        }
        return false;
    }

    /**
     * The request after the budgets: a challenged request goes through the
     * gate (pass cookie, solution, crawler, exempt path, or the page).
     *
     * @return array{decision: Decision, cookies: list<string>, page: ?string, json: ?array{algorithm: string, challenge: string, maxnumber: int, salt: string, signature: string}, passed: bool}
     */
    public function settle(Decision $decision, Request $request, float $now): array
    {
        if ($decision->action !== Decision::CHALLENGE) {
            return ['decision' => $decision, 'cookies' => [], 'page' => null, 'json' => null, 'passed' => false];
        }
        $r = $this->gate()->resolve($decision, $this->base, $request, $now, $this->gateOptions($decision, $request));
        return $r + ['passed' => $r['decision']->passes()];
    }

    /**
     * How the gate answers this request: an API gets the task as JSON; a
     * form comes back after the check (a pause would lose what was typed);
     * a spent budget's solution starts the budget's counter again.
     *
     * @return array{solution: ?string, fresh: ?int, api: bool, earn: array{window: int}|null, resend: array{action: string, fields: list<array{0: string, 1: string}>}|false|null}
     */
    private function gateOptions(Decision $d, Request $request): array
    {
        $api = $this->isApi($request);
        $budget = $d->spent ? ($this->settings->budgets[$d->reason] ?? null) : null;
        return [
            'solution' => $this->postedSolution(),
            // challenge … max-age: a pass issued at most that long ago.
            'fresh' => $d->reason === 'always' ? $this->alwaysAge : null,
            'api' => $api,
            'earn' => $budget !== null ? ['window' => $budget->window, 'counter' => $budget->counter()] : null,
            'resend' => !$api && $request->method !== 'GET' && $request->method !== 'HEAD' ? self::resendFields($request) : null,
        ];
    }

    /**
     * Whether a request is an API's: it asks for or sends JSON, a page's
     * script sent it in the background (isBackground()), or its path is one
     * the site named (api-path). A check is then a header, not a page.
     */
    public function isApi(Request $request): bool
    {
        if (self::isBackground($request)) {
            return true;
        }
        $sent = $this->request === $request ? ($_SERVER['CONTENT_TYPE'] ?? '') : '';
        foreach ([(string) $request->header('accept'), is_string($sent) ? $sent : ''] as $type) {
            if ($type !== '' && preg_match('#application/(?:[\w.+-]+\+)?json#i', $type) === 1 && stripos($type, 'text/html') === false) {
                return true;
            }
        }
        foreach ($this->settings->challenge->apiPaths as $p) {
            if (@preg_match($p, $request->matchPath()) === 1) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a page's script sent the request in the background -- fetch() or
     * XMLHttpRequest, not the browser for a page, a frame or an image: the
     * browser says so (Sec-Fetch-Dest: empty), and libraries do
     * (X-Requested-With: XMLHttpRequest) where an older browser does not.
     * Such a request cannot show the check page or run it: it gets the check
     * as JSON (429, Request-Shield-Challenge) like an API, so the script can
     * tell a check from the content it asked for. A client that sends the
     * headers without being one gets that answer too -- no way past the check.
     */
    public static function isBackground(Request $request): bool
    {
        return strcasecmp((string) $request->header('sec-fetch-dest'), 'empty') === 0
            || strcasecmp((string) $request->header('x-requested-with'), 'XMLHttpRequest') === 0;
    }

    /**
     * The answer the check inside the form sent with a form (hidden field),
     * taken out of $_POST once read -- the application never sees it.
     */
    private function postedSolution(): ?string
    {
        if ($this->settings->challenge->widgetPath === null) {
            return null;
        }
        $field = $this->settings->challenge->solutionCookie;
        $v = $_POST[$field] ?? null;
        unset($_POST[$field]);
        if (is_string($v) && $v !== '') {
            $this->posted = $v;
        }
        return $this->posted;
    }

    private ?string $posted = null;

    /**
     * The placeholder for the check inside a form, and (once per page) the
     * script: echo Shield::active()?->widget(); -- empty while the widget is
     * off (set widget-path ...).
     *
     * @param string $start "input" (the first input into the form), "load" or "submit"
     */
    public function widget(string $start = 'input'): string
    {
        try {
            $w = $this->settings->challenge->widgetPath;
            return $w === null || $this->settings->mode === 'off' ? '' : \CjwNetwork\RequestShield\Challenge\Widget::html($w, $start);
        } catch (\Throwable $e) {
            self::failed('widget', 'widget() failed, the form has no check: ' . $e->getMessage());
            return '';                              // fail safe: the form works without the check
        }
    }

    /** Whether widget() gives a check (set widget-path, mode not off) -- asking it costs nothing and sends no script. */
    public function hasWidget(): bool
    {
        return $this->settings->challenge->widgetPath !== null && $this->settings->mode !== 'off';
    }

    /** <widgetPath>/challenge (a task as JSON) and <widgetPath>/widget.js. */
    private function serveWidget(string $what, Request $request, float $now): void
    {
        $c = $this->settings->challenge;
        if ($what === 'widget.js') {
            $js = \CjwNetwork\RequestShield\Challenge\Widget::script();
            $etag = '"' . substr(hash('sha256', $js), 0, 16) . '"';
            header('Content-Type: text/javascript; charset=utf-8');
            header('Cache-Control: public, max-age=86400');
            header('ETag: ' . $etag);
            if (($request->header('if-none-match') ?? '') === $etag) {
                http_response_code(304);
                return;
            }
            echo $js;
            return;
        }
        if ($what !== 'challenge') {
            http_response_code(404);
            return;
        }
        $texts = Texts::all(Texts::language($c->language, $request->header('accept-language'), $c->texts), $c->texts);
        $task = $this->gate()->widgetTask($request, $now);
        $until = $task === null ? $this->gate()->passUntil($request, $now) : 0;
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('Vary: Accept-Language');
        header('X-Robots-Tag: noindex');
        echo json_encode([
            'passed' => $task === null,
            // With a pass: until when it holds; the widget fetches a task before then.
            'until' => $task === null ? $until : null,
            'challenge' => $task,
            'field' => $c->solutionCookie,
            'texts' => ['checking' => $texts['widget-checking'], 'checked' => $texts['widget-checked'], 'failed' => $texts['widget-failed']],
            // The box's "?": the check in plain words, for visitors (set docs-url off: none).
            'about' => ($about = Help::explained($this->settings->docsUrl)) !== null ? ['url' => $about, 'text' => $texts['about']] : null,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP);
    }

    /**
     * For the application: go on only with a browser that passed the check.
     * With a valid pass (issued in the last $fresh seconds, when given) this
     * returns; otherwise the visitor gets the check page and the request
     * ends here -- for a form, with its fields, which are sent again once the
     * check is done, so nothing typed is lost:
     *
     *   Shield::active()?->requirePass();        // before saving a comment
     *   Shield::active()?->requirePass(300);     // a pass from the last 5 minutes
     *
     * Call it before acting on the request. Forms with files, or larger than
     * 256 KB, cannot be carried through: the visitor is asked to send them
     * again (better: require the pass on the form's page, before).
     */
    public function requirePass(?int $fresh = null): void
    {
        try {
            $this->requirePassNow($fresh);
        } catch (\Throwable $e) {
            self::failed('requirePass', 'requirePass() failed and let the request through: ' . $e->getMessage());
        }
    }

    /** requirePass() proper. */
    private function requirePassNow(?int $fresh): void
    {
        $request = $this->request;
        if ($request === null || $this->settings->mode === 'off' || ($this->passed && $fresh === null)) {
            return;
        }
        $now = microtime(true);
        // The answer out of the form first: a used one must not be sent again with it.
        $solution = $this->postedSolution();
        $resend = $request->method === 'GET' || $request->method === 'HEAD' ? null : self::resendFields($request);
        $r = $this->gate()->resolve(Decision::challenge('app'), Decision::allowUncached('app'), $request, $now,
            ['forced' => true, 'fresh' => $fresh, 'resend' => $resend, 'solution' => $solution]);
        if (!headers_sent()) {
            foreach ($r['cookies'] as $cookie) {
                header('Set-Cookie: ' . $cookie, false);
            }
        }
        if ($r['decision']->passes()) {
            $this->passed = true;
            return;
        }
        if ($this->settings->mode === 'monitor') {
            $this->watched($r['decision'], $request, $now, $this);
            return;
        }
        $this->stop($r['decision'], $request, $r['page'], $now);
        exit;
    }

    /** Answers with the check page (or a status page) instead of the application's. */
    /** @param array{algorithm: string, challenge: string, maxnumber: int, salt: string, signature: string}|null $json the task for an API */
    private function stop(Decision $d, Request $request, ?string $page, float $now, bool $echo = true, ?array $json = null, bool $log = true): string
    {
        $s = $this->settings;
        $rule = $this->explain($d, $request);
        $reference = $page === null && $json === null ? ErrorPage::reference() : null;      // a refusal page's reference (0030)
        if ($log) {
            Log::note($s, $request, $d, $rule, $now, false, $reference);
        }
        while ($echo && ob_get_level() > 0) {
            ob_end_clean();                 // nothing of the application's page
        }
        if ($json !== null) {
            $body = (new Responder())->api($d, $json, $s->debugHeader, $rule);
            if ($echo) {
                echo $body;
            }
            return $body;
        }
        $c = $s->challenge;
        $texts = Texts::all(Texts::language($c->language, $request->header('accept-language'), $c->texts), $c->texts);
        $responder = new Responder();
        if ($page === null && $this->isApi($request)) {
            // A program: the refusal as JSON (0030).
            $responder->headers($d, $s->debugHeader, $rule, false, true);
            $body = $request->method === 'HEAD' ? '' : json_encode(ErrorPage::json($d, $reference), JSON_UNESCAPED_SLASHES) . "\n";
        } else {
            [$body, $builtIn] = $responder->page($d, $page, $texts, $c->home, PageHook::asker($s), $request, $c->logo, $reference, $s->errorPages);
            $responder->headers($d, $s->debugHeader, $rule, $builtIn);
            $body = $request->method === 'HEAD' ? '' : $body;
        }
        if ($echo) {
            echo $body;
        }
        return $body;
    }

    /**
     * A form's fields as the application got them, to put in the check page;
     * false when they cannot be carried (files, too large, too many).
     *
     * @return array{action: string, fields: list<array{0: string, 1: string}>}|false
     */
    private static function resendFields(Request $request)
    {
        foreach ($_FILES as $file) {
            if (is_array($file) && ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
                return false;
            }
        }
        $fields = [];
        $bytes = 0;
        $walk = static function (array $values, string $prefix) use (&$walk, &$fields, &$bytes): bool {
            foreach ($values as $key => $value) {
                $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
                if (is_array($value)) {
                    if (!$walk($value, $name)) {
                        return false;
                    }
                    continue;
                }
                $value = is_scalar($value) ? (string) $value : '';
                $fields[] = [$name, $value];
                $bytes += strlen($name) + strlen($value);
                if ($bytes > self::RESEND_MAX_BYTES || count($fields) > 1000) {
                    return false;
                }
            }
            return true;
        };
        /** @var array<mixed> $post */
        $post = $_POST;
        return $walk($post, '') ? ['action' => $request->rawUri, 'fields' => $fields] : false;
    }

    /**
     * X-RS-Check: 1[; fresh=<seconds>] from the application, on a page (a
     * form's): the page is kept back until it is finished; without a pass the
     * visitor gets the check page instead. The header never reaches the
     * browser.
     */
    private function watchForChallengeHeader(): void
    {
        $decided = null;
        ob_start(function (string $buffer, int $phase) use (&$decided): string {
            try {
                if ($decided === null) {
                    $decided = '';
                    foreach (headers_list() as $h) {
                        if (preg_match('/^X-RS-Check:\s*(.*)$/i', $h, $m)) {
                            header_remove('X-RS-Check');
                            $page = $this->challengeFor(trim($m[1]));
                            if ($page !== null) {
                                $decided = $page;
                            }
                            break;
                        }
                    }
                    if ($decided !== '') {
                        return $decided;
                    }
                    $decided = false;
                }
                return $decided === false ? $buffer : '';     // after the check page: nothing of the application's
            } catch (\Throwable $e) {
                self::failed('app-challenge', 'the check the application asked for failed, its page went out: ' . $e->getMessage());
                $decided = false;
                return $buffer;                               // fail safe: the application's page as it is
            }
        });
    }

    /** The check page for a page the application marked, or null when the visitor has a pass. */
    private function challengeFor(string $value): ?string
    {
        $request = $this->request;
        if ($request === null || !preg_match('/^1\s*(?:;|$)/', $value)) {
            return null;
        }
        $fresh = preg_match('/fresh=(\d+)/', $value, $m) ? (int) $m[1] : null;
        if ($this->passed && $fresh === null) {
            return null;
        }
        $now = microtime(true);
        $r = $this->gate()->resolve(Decision::challenge('app'), Decision::allowUncached('app'), $request, $now, ['forced' => true, 'fresh' => $fresh]);
        foreach ($r['cookies'] as $cookie) {
            header('Set-Cookie: ' . $cookie, false);
        }
        if ($r['decision']->passes()) {
            $this->passed = true;
            return null;
        }
        if ($this->settings->mode === 'monitor') {
            $this->watched($r['decision'], $request, $now, $this);
            return null;
        }
        return $this->stop($r['decision'], $request, $r['page'], $now, false);
    }

    /**
     * Counts one event against a budget that no rule counts by itself -- a
     * cache miss, a failed sign-in -- and says what the client has earned.
     * Budgets marked 'onDemand' => true in the configuration are only counted here.
     */
    public function consume(string $budget, ?Request $request = null, ?float $now = null, bool $answer = false): Decision
    {
        try {
            return $this->consumeNow($budget, $request, $now, $answer);
        } catch (\Throwable $e) {
            self::failed('consume', "consume($budget) failed and let the request through: " . $e->getMessage());
            return Decision::allowUncached('shield error');
        }
    }

    /** consume() proper. */
    private function consumeNow(string $budget, ?Request $request, ?float $now, bool $answer): Decision
    {
        $b = $this->settings->budgets[$budget] ?? null;
        $request ??= $this->request;
        if ($request === null || $this->settings->mode === 'off') {
            return Decision::allow();
        }
        $now ??= microtime(true);
        if ($b === null) {
            // Only a rule marked "monitor" has it: counted and logged, never acted on.
            $this->watchBudget($budget, $request, $now);
            return Decision::allow();
        }
        $times = $this->base->action === Decision::ALLOW_UNCACHED ? $this->settings->uncachedWeight : 1;
        $d = $this->budgetRule($b)->check($request, $now, $times) ?? Decision::allow();
        if (!$d->passes()) {
            $this->signal($budget, $request, $now);              // ban after 10 logins in 15m
        }
        if ($this->settings->mode === 'monitor') {
            if (!$d->passes()) {
                $this->watched($d, $request, $now, $this);
                return Decision::allowUncached($budget);
            }
            return $d;
        }
        if ($d->passes()) {
            $this->watchBudget($budget, $request, $now);
        }
        // A spent budget that lets its client earn it back: a solution sent
        // with this request (the form again, an API's header) starts it again.
        if ($d->spent) {
            $r = $this->gate()->resolve($d, Decision::allowUncached($budget), $request, $now, $this->gateOptions($d, $request));
            if (!headers_sent()) {
                foreach ($r['cookies'] as $cookie) {
                    header('Set-Cookie: ' . $cookie, false);
                }
            }
            if ($r['decision']->passes()) {
                return $r['decision'];
            }
            if ($answer) {
                $this->stop($r['decision'], $request, $r['page'], $now, true, $r['json']);
                exit;
            }
            return $d;
        }
        if ($d->action !== Decision::ALLOW && ($this->settings->logFile !== null || $this->settings->liveEnabled)) {
            Log::note($this->settings, $request, $d, $this->explain($d, $request), $now);
        }
        // answer: true -- the shield answers a refusal itself (a pause, the
        // check) and the request ends here: Shield::active()?->consume('posts', answer: true)
        if ($answer && !$d->passes()) {
            $this->stop($d, $request, null, $now, true, null, false);
            exit;
        }
        return $d;
    }

    /** An on-demand budget of the rules marked "monitor": what it would decide, logged. */
    private function watchBudget(string $budget, Request $request, float $now): void
    {
        $m = $this->settings->monitor;
        $w = $this->watcher($request);
        if ($m === null || $w === null || !isset($m->budgets[$budget])) {
            return;
        }
        $d = $w->budgetRule($m->budgets[$budget])->check($request, $now);
        if ($d !== null && !$d->passes()) {
            $this->watched($d, $request, $now, $w);
        }
    }

    private function budgetRule(Budget $b): BudgetRule
    {
        return new BudgetRule($this->store, $b->name, $b->limit, $b->window, $b->challengeAt,
            $this->settings->exemptIps, $this->settings->ipv6Prefix, $b->earnBack, $b->counter(), $b->paths);
    }

    private function gate(): Gate
    {
        $c = $this->settings->challenge;
        return new Gate($c, Secret::resolve($c->secret, $this->settings->storeDir),
            $this->settings->crawlers === [] ? null : $this->crawlers(), $this->settings->ipv6Prefix, $this->store,
            PageHook::asker($this->settings), $this->settings->docsUrl);
    }

    private ?Crawlers $crawlers = null;

    /**
     * The known crawlers, with what verifying them costs remembered for a day
     * per address (APCu, else files in store-dir) and DNS lookups limited
     * (dns-lookups a minute, for all requests together).
     */
    public function crawlers(): Crawlers
    {
        if ($this->crawlers !== null) {
            return $this->crawlers;
        }
        $c = $this->settings->challenge;
        $dir = $this->settings->storeDir;
        $apcu = ApcuStore::usable();
        return $this->crawlers = Crawlers::of($this->settings,
            static function (string $key) use ($apcu, $dir): ?string {
                if ($apcu) {
                    $v = apcu_fetch('rshield:' . $key);
                    return is_string($v) ? $v : null;
                }
                $f = $dir . '/se/' . md5($key);
                $mtime = @filemtime($f);
                if ($mtime === false || $mtime <= time() - 86400) {
                    return null;
                }
                $v = @file_get_contents($f);
                return is_string($v) ? $v : null;
            },
            static function (string $key, string $value) use ($apcu, $dir): void {
                if ($apcu) {
                    apcu_store('rshield:' . $key, $value, 86400);
                    return;
                }
                Files::write($dir . '/se/' . md5($key), $value);
            },
            // New DNS lookups per minute, for all requests together (the store).
            function () use ($c): bool {
                return $c->dnsLookups > 0 && $this->store->hit('se-lookups', 60, microtime(true)) <= $c->dnsLookups;
            },
        );
    }

    /**
     * The store this shield counts in -- for a page that shows what a request
     * would meet now (the demo's answer, Inspector), never written through here.
     */
    public function store(): Store
    {
        return $this->store;
    }

    /** The store the settings ask for ("auto": APCu when usable, else files). */
    public static function storeFor(Settings $s): Store
    {
        return match ($s->store) {
            'apcu' => new ApcuStore(),
            'file' => new FileStore($s->storeDir),
            'memory' => new MemoryStore(),
            default => ApcuStore::usable() ? new ApcuStore() : new FileStore($s->storeDir),
        };
    }
}
