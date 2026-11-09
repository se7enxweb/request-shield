<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

namespace CjwNetwork\RequestShield;

/**
 * The modes of what the shield creates: its folders (store-dir, the log's,
 * the statistics', the lists', the feeds', the HTTP cache's) and its files
 * (the log, the statistics, the lists, the feeds, marks, a learning run, the
 * advice) -- `set dir-mode` and `set file-mode`, by default 0700 and 0600:
 * only the user PHP runs as. A server's own rules for new folders (0750,
 * 02770 so the group is inherited, 0755) are set exactly: a new folder or
 * file gets its mode with chmod() after it is made and before anything is
 * written into it, so the umask takes nothing away and adds nothing. What
 * exists keeps its mode; a file written whole is a new file.
 *
 * Never allowed: writing for everyone, and a mode that keeps PHP itself from
 * writing (the owner's rw, for a folder rwx). The secret stays 0600 and the
 * compiled settings 0600 in a 0700 folder whatever is set: they hold the key.
 *
 * The modes are taken from the settings when they are made (Settings'
 * constructor) -- the one place every request and every command passes
 * before it writes.
 */
final class Files
{
    private static int $fileMode = 0600;

    private static int $dirMode = 0700;

    /** Whether to append as with threads (ZTS: no umask); null: as PHP is built (a test sets it) */
    /** @phpstan-ignore property.unusedType */
    private static ?bool $threads = null;

    /** Whether a mode may be a file's: the owner reads and writes, nobody else writes everyone's, no special bits. */
    public static function fileModeOk(int $mode): bool
    {
        return ($mode & ~0777) === 0 && ($mode & 0600) === 0600 && ($mode & 0002) === 0 && ($mode & 0111) === 0;
    }

    /** Whether a mode may be a folder's: the owner rwx, not writable for everyone; setgid and sticky allowed. */
    public static function dirModeOk(int $mode): bool
    {
        return ($mode & ~03777) === 0 && ($mode & 0700) === 0700 && ($mode & 0002) === 0;
    }

    /** "0640", "640", "02770" as a number; null when it is no mode. */
    public static function parseMode(string $value): ?int
    {
        return preg_match('/^0?[0-7]{3,4}$/', $value) === 1 ? (int) octdec($value) : null;
    }

    /** Takes the modes of the settings (Settings' constructor); a mode that is not allowed keeps the default. */
    public static function modes(int $file, int $dir): void
    {
        self::$fileMode = self::fileModeOk($file) ? $file : 0600;
        self::$dirMode = self::dirModeOk($dir) ? $dir : 0700;
    }

    public static function fileMode(): int
    {
        return self::$fileMode;
    }

    public static function dirMode(): int
    {
        return self::$dirMode;
    }

    /** A folder, with the parents it lacks, each in dir-mode exactly; true when it is there. */
    public static function dir(string $dir): bool
    {
        if (is_dir($dir)) {
            return true;
        }
        $missing = [];
        for ($d = $dir; $d !== '' && $d !== '.' && $d !== '/' && !is_dir($d); $d = dirname($d)) {
            $missing[] = $d;
            if (dirname($d) === $d) {
                break;
            }
        }
        if (!@mkdir($dir, self::$dirMode & 0777, true) && !is_dir($dir)) {
            return false;               // another process may have made it in between: is_dir() decides
        }
        foreach ($missing as $d) {
            @chmod($d, self::$dirMode);   // exactly: setgid, and what the umask took
        }
        return true;
    }

    /**
     * Whether a folder is gone, asked of the disk: a write into it failed,
     * and PHP's stat cache may still remember it from before logrotate or a
     * clean-up removed it -- is_dir() would say it is there, and nothing
     * would be made anew.
     */
    private static function lost(string $dir): bool
    {
        clearstatcache(true, $dir);
        return !is_dir($dir);
    }

    /**
     * A file written whole: a temporary file made exclusive in file-mode
     * (create()), then the data, then renamed -- a reader never sees half of it, and
     * the data is never in a file of another mode. $keep: the read and write
     * bits of the file it replaces (a file named by the user, read by
     * something else).
     */
    public static function write(string $file, string $data, string $suffix = '', bool $keep = false): bool
    {
        if (!self::dir(dirname($file))) {
            return false;
        }
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . $suffix;
        $old = $keep ? @fileperms($file) : false;
        $h = self::create($tmp, $old !== false ? $old & 0666 : self::$fileMode);
        if ($h === false) {
            return false;
        }
        $ok = @fwrite($h, $data) === strlen($data);
        fclose($h);
        if (!$ok || !@rename($tmp, $file)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    /**
     * A new file, exclusive, open for writing, in $mode from the start: made
     * with the umask $mode's complement (no x, no special bits: exact) -- a
     * handle opened on it in between could read what is written later. With
     * threads (ZTS, the umask is the process's) made, then chmod. A file
     * system without modes refuses chmod: written all the same.
     *
     * @return resource|false
     */
    public static function create(string $file, int $mode)
    {
        if (!(self::$threads ?? ZEND_THREAD_SAFE)) {
            $umask = umask(0777 & ~$mode);
            try {
                return @fopen($file, 'xb');
            } finally {
                umask($umask);
            }
        }
        $h = @fopen($file, 'xb');
        if ($h !== false) {
            @chmod($file, $mode);
        }
        return $h;
    }

    /**
     * A line added to a file (O_APPEND: the lines of parallel requests do not
     * overwrite each other). A new file is made in file-mode at once: the
     * umask is file-mode's complement for that one call (a file mode has no
     * x and no special bits, so the result is exact) -- no second look, no
     * moment in another mode. With threads (ZTS) the umask is the whole
     * process's: then the file is opened, and one still empty (just made, by
     * this request or a parallel one) gets file-mode before the line. A
     * missing folder is made. $lock: an exclusive lock while writing.
     */
    public static function append(string $file, string $data, bool $lock = false): bool
    {
        if (!(self::$threads ?? ZEND_THREAD_SAFE)) {
            $umask = umask(0777 & ~self::$fileMode);
            try {
                $ok = @file_put_contents($file, $data, FILE_APPEND | ($lock ? LOCK_EX : 0));
            } finally {
                umask($umask);
            }
            if ($ok === false && self::lost(dirname($file)) && self::dir(dirname($file))) {
                return self::append($file, $data, $lock);
            }
            return $ok !== false;
        }
        $h = @fopen($file, 'ab');
        if ($h === false && self::lost(dirname($file)) && self::dir(dirname($file))) {
            $h = @fopen($file, 'ab');
        }
        if ($h === false) {
            return false;
        }
        $st = fstat($h);
        if (is_array($st) && $st['size'] === 0 && ($st['mode'] & 07777) !== self::$fileMode) {
            @chmod($file, self::$fileMode);
        }
        if ($lock) {
            flock($h, LOCK_EX);
        }
        $ok = @fwrite($h, $data) === strlen($data);
        fclose($h);
        return $ok;
    }
}
