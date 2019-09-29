<?php

/**
 * Checks for vulnerabilities at wpvulndb.com.
 *
 * @author markri http://github.com/markri
 * @license MIT
 */

if (!class_exists('WP_CLI')) {
    // Whoops, something is wrong
    return;
}

if (!class_exists('WpSecCheck')) {

    class WpSecCheck
    {
        const OUTPUT_USER = 'user';
        const OUTPUT_JSON = 'json';
        const OUTPUT_NAGIOS = 'nagios';

        const API_V2 = 'v2';
        const API_V3 = 'v3';

        private $outputType = true;
        private $cached = false;    // No caching as default. Don't exceed 30 calls for every 30 seconds
        private $cacheTTL = 28800;  // default to 8 hours
        private $APIversion = self::API_V2;    // Defaults to 2 for easy usage, use 3 for new API
        private $token = null;      // Token to use for API v3

        private $coreVulnerabilityCount = 0;
        private $coreVulnerabilities = array();
        private $pluginVulnerabilityCount = 0;
        private $pluginVulnerabilities = array();
        private $themeVulnerabilityCount = 0;
        private $themeVulnerabilities = array();
        private $cacheHitCount = 0;
        private $vulndbRequestCount = 0;


        /**
         * @param $ags
         * @param $assoc_args
         */
        public function __invoke($ags, $assoc_args)
        {
            // Parse user options
            $checkCore = true;
            $checkThemes = true;
            $checkPlugins = true;

            switch ($assoc_args['type']) {
                case 'core':
                    $checkThemes = false;
                    $checkPlugins = false;
                    break;
                case 'themes':
                    $checkCore = false;
                    $checkPlugins = false;
                    break;
                case 'plugins':
                    $checkCore = false;
                    $checkThemes = false;
                    break;
                default:
                    break;
            }

            $this->outputType = $assoc_args['output'];

            $this->cached = isset($assoc_args['cached']);

            $this->cacheTTL = isset($assoc_args['ttl']) ? $assoc_args['ttl'] : $this->cacheTTL;
            $this->APIversion = isset($assoc_args['api']) ? $assoc_args['api'] : $this->APIversion;
            $this->token = isset($assoc_args['token']) ? $assoc_args['token'] : $this->token;

            // Validate wordpress installation
            $output = WP_CLI::runcommand('core is-installed', array(
              'return' => 'all',
              'exit_error' => false,
            ));
            if ($output->return_code == 1) {
                WP_CLI::error('No wordpress installation found');
            }

            // Execute
            if ($checkCore) {
                $this->checkCoreVulnerability();
            }

            if ($checkPlugins) {
                $this->checkPluginVulnerabilities();
            }

            if ($checkThemes) {
                $this->checkThemeVulnerabilities();
            }

            // Output
            switch ($this->outputType) {
                case self::OUTPUT_USER:
                    if ($this->coreVulnerabilityCount == 0 && $this->pluginVulnerabilityCount == 0 && $this->themeVulnerabilityCount == 0) {
                        WP_CLI::line('-----------------------------------------------');
                        WP_CLI::line('');
                        WP_CLI::success('No vulnerabilities found');
                    } else {
                        WP_CLI::line('-----------------------------------------------');
                        WP_CLI::line('');
                        WP_CLI::warning(
                            sprintf(
                                '%s core, %s plugin and %s theme vulnerabilities found',
                                $this->coreVulnerabilityCount,
                                $this->pluginVulnerabilityCount,
                                $this->themeVulnerabilityCount
                            )
                        );
                    }

                    break;
                case self::OUTPUT_NAGIOS:
                    if ($this->coreVulnerabilityCount == 0 && $this->pluginVulnerabilityCount == 0 && $this->themeVulnerabilityCount == 0) {
                        WP_CLI::line('OK - no vulnerabilities found | vulns=0');
                        exit(0);
                    } else {
                        WP_CLI::line(
                            sprintf(
                                'CRITICAL - %s core, %s plugin and %s theme vulnerabilities found | vulns=%s',
                                $this->coreVulnerabilityCount,
                                $this->pluginVulnerabilityCount,
                                $this->themeVulnerabilityCount,
                                $this->coreVulnerabilityCount + $this->pluginVulnerabilityCount + $this->themeVulnerabilityCount
                            )
                        );
                        exit(2);
                    }
                    break;
                case self::OUTPUT_JSON:

                    $output = array();

                    if ($checkCore) {
                        $output['core'] = array(
                            'count'   => $this->coreVulnerabilityCount,
                            'details' => $this->coreVulnerabilities,
                        );
                    }

                    if ($checkPlugins) {
                        $output['plugins'] = array(
                            'count'   => $this->pluginVulnerabilityCount,
                            'details' => $this->pluginVulnerabilities,
                        );
                    }

                    if ($checkThemes) {
                        $output['themes'] = array(
                            'count'   => $this->themeVulnerabilityCount,
                            'details' => $this->themeVulnerabilities,
                        );
                    }

                    $output['hits'] = array(
                        'cache hits'       => $this->cacheHitCount,
                        'wpvulndb queries' => $this->vulndbRequestCount,
                    );

                    WP_CLI::line(json_encode($output));

                    break;
            }
        }

        /**
         * Checks core version at wpvulndb.
         */
        private function checkCoreVulnerability()
        {
            // Get version through internal WP_CLI command
            $output = WP_CLI::runcommand('core version', array(
              'return' => 'all',
              'exit_error' => false,
            ));
            $coreVersion = trim($output->stdout);

            switch ($this->outputType) {
                case self::OUTPUT_JSON:
                    break;
                case self::OUTPUT_NAGIOS:
                    break;
                default:
                    WP_CLI::line('');
                    WP_CLI::line('-----------------------------------------------');
                    WP_CLI::line(sprintf('Checking core vulnerabilities for version %s', $coreVersion));
                    WP_CLI::line('-----------------------------------------------');
                    WP_CLI::line('');
                    break;
            }

            // Connect to wpvulndb
            $parameter = intval(str_replace('.', '', $coreVersion));

            $cache = WP_CLI::get_cache();
            $cache_key = sprintf("wp-sec/core-%s.json", $parameter);
            $cache_file = $cache->has( $cache_key, $this->cacheTTL );

            if ($cache_file && $this->cached) {
                $req = unserialize($cache->read($cache_key));
                ++$this->cacheHitCount;
            }
            else {
                if ($this->APIversion == self::API_V2) {
                    $url = sprintf('https://wpvulndb.com/api/v2/wordpresses/%s', $parameter);
                    $req = WP_CLI\Utils\http_request('GET', $url);
                } else {
                    $url = sprintf('https://wpvulndb.com/api/v3/wordpresses/%s', $parameter);
                    $req = WP_CLI\Utils\http_request('GET', $url, null, array('Authorization' => sprintf('Token token=%s', $this->token)));
                }

                ++$this->vulndbRequestCount;

                $cache->write($cache_key, serialize($req));
            }

            $json = json_decode($req->body, true);

            if ( '20' != substr( $req->status_code, 0, 2 ) ) {
                WP_CLI::error(sprintf('Couldn\'t check wpvulndb @ %s (HTTP code %s)', $url, $req->status_code));
            }

            if (!array_key_exists($coreVersion, $json)) {
                WP_CLI::error(sprintf('Version %s not found on wpvulndb', $coreVersion));
            }

            // Process found vulnerabilities
            $vulnerabilities = $json[$coreVersion]['vulnerabilities'];
            $this->coreVulnerabilityCount = count($vulnerabilities);
            $this->coreVulnerabilities = $vulnerabilities;

            if (empty($vulnerabilities)) {
                switch ($this->outputType) {
                    case self::OUTPUT_JSON:
                        break;
                    case self::OUTPUT_NAGIOS:
                        break;
                    default:
                        WP_CLI::line(sprintf('No known core vulnerabilities found in version %s', $coreVersion));
                        WP_CLI::line('');
                        break;
                }

                return;
            }

            switch ($this->outputType) {
                case self::OUTPUT_JSON:
                    break;
                case self::OUTPUT_NAGIOS:
                    break;
                default:
                    WP_CLI::line('');
                    WP_CLI::line(sprintf('Found %s core vulnerabilities:', count($vulnerabilities)));
                    break;
            }

            foreach ($vulnerabilities as $vulnerability) {
                switch ($this->outputType) {
                    case self::OUTPUT_JSON:
                        break;
                    case self::OUTPUT_NAGIOS:
                        break;
                    default:
                        WP_CLI::line('-----------------------------');
                        WP_CLI::line(sprintf('Title: %s', $vulnerability['title']));

                        if (array_key_exists('cve', $vulnerability['references'])) {
                            $cves = $vulnerability['references']['cve'];
                            WP_CLI::line(sprintf('CVE\'s: %s', implode(', ', $cves)));
                        }

                        WP_CLI::line(
                            sprintf(
                                'Fixed in: %s',
                                array_key_exists('fixed_in', $vulnerability) ? $vulnerability['fixed_in'] : 'fix n/a'
                            )
                        );
                        break;
                }
            }

            return true;
        }

        /**
         * Check plugins at wpvulndb.
         */
        private function checkPluginVulnerabilities()
        {
            $this->pluginVulnerabilityCount = 0;
            $output = WP_CLI::runcommand('plugin list --format=json', array(
              'return' => 'all',
              'exit_error' => false,
            ));
            $plugins = json_decode($output->stdout, true);

            if (null === $plugins) {
                WP_CLI::error('No plugins found? Try `wp plugin list` to check for errors');
                return;
            }

            switch ($this->outputType) {
                case self::OUTPUT_JSON:
                    break;
                case self::OUTPUT_NAGIOS:
                    break;
                default:
                    WP_CLI::line('');
                    WP_CLI::line('-------------------------------');
                    WP_CLI::line('Checking plugin vulnerabilities');
                    WP_CLI::line('-------------------------------');
                    WP_CLI::line('');
                    WP_CLI::line('Vulnerabilities:');
                    break;
            }

            foreach ($plugins as $plugin) {
                $title = $plugin['name'];

                if (in_array($plugin['status'], array('must-use','dropin'), true )) {
                    // these types of plugins cannot be checked on wpvulndb
                    continue;
                }

                $version = $plugin['version'];

                $cache = WP_CLI::get_cache();
                $cache_key = sprintf("wp-sec/plugin-%s-%s.json", $title, $version);
                $cache_file = $cache->has( $cache_key, $this->cacheTTL );

                if ($cache_file && $this->cached) {
                    $req = unserialize($cache->read($cache_key));
                    ++$this->cacheHitCount;
                }
                else {

                    if ($this->APIversion == self::API_V2) {
                        $url = sprintf('https://wpvulndb.com/api/v2/plugins/%s', $title);
                        $req = WP_CLI\Utils\http_request('GET', $url);
                    } else {
                        $url = sprintf('https://wpvulndb.com/api/v3/plugins/%s', $title);
                        $req = WP_CLI\Utils\http_request('GET', $url, null, array('Authorization' => sprintf('Token token=%s', $this->token)));
                    }

                    ++$this->vulndbRequestCount;

                    $cache->write($cache_key, serialize($req));
                }

                $json = json_decode($req->body, true);

                if ( $req->status_code  == '404') {
                    // For plugins we continue, because not every plugin has a vulnerability and therfore no entry at wpvulndb.com
                    continue;
                } else if('20' != substr( $req->status_code, 0, 2 )) {
                    WP_CLI::error(sprintf('Couldn\'t check wpvulndb @ %s (HTTP code %s)', $url, $req->status_code));
                }

                $json_entry = NULL;
                foreach ($json as $entry_title => $entry) {
                    if (strtolower($title) == strtolower($entry_title)) {
                        $json_entry = $entry;
                        break;
                    }
                }
                if ($json_entry === NULL) {
                    WP_CLI::error(sprintf('Unexpected response from wpvulndb for plugin %s', $title));
                }

                $vulnerabilities = $json_entry['vulnerabilities'];

                $pluginVulnerabilities = array(
                    'title'   => $title,
                    'version' => $version,
                    'status'  => $plugin['status'],
                    'details' => array(),
                    'count'   => 0
                );

                foreach ($vulnerabilities as $vulnerability) {
                    $safeVersion = $vulnerability['fixed_in'];

                    if (!$this->isVersionLessThan($version, $safeVersion)) {
                        continue;
                    }

                    ++$this->pluginVulnerabilityCount;
                    ++$pluginVulnerabilities['count'];
                    $pluginVulnerabilities['details'][] = $vulnerability;

                    switch ($this->outputType) {
                        case self::OUTPUT_JSON:
                            break;
                        case self::OUTPUT_NAGIOS:
                            break;
                        default:
                            WP_CLI::line('-----------------------------');
                            WP_CLI::line(sprintf('Plugin: %s', $title));
                            WP_CLI::line(sprintf('Version: %s', $version));
                            WP_CLI::line(sprintf('Vulnerability: %s', $vulnerability['title']));

                            if (array_key_exists('cve', $vulnerability['references'])) {
                                $cves = $vulnerability['references']['cve'];
                                WP_CLI::line(sprintf('CVE\'s: %s', implode(', ', $cves)));
                            }

                            WP_CLI::line(
                                sprintf(
                                    'Fixed in: %s',
                                    empty($vulnerability['fixed_in']) ? 'fix n/a' : $vulnerability['fixed_in']
                                )
                            );

                            break;
                    }
                }

                if ($pluginVulnerabilities['count'] > 0) {
                    $this->pluginVulnerabilities[] = $pluginVulnerabilities;
                }

            }

            if ($this->pluginVulnerabilityCount === 0) {
                switch ($this->outputType) {
                    case self::OUTPUT_JSON:
                        break;
                    case self::OUTPUT_NAGIOS:
                        break;
                    default:
                        WP_CLI::line('No known plugin vulnerabilities found');
                        break;
                }
            }
        }

        private function checkThemeVulnerabilities()
        {
            $this->themeVulnerabilityCount = 0;
            $output = WP_CLI::runcommand('theme list --format=json', array(
              'return' => 'all',
              'exit_error' => false,
            ));
            $themes = json_decode($output->stdout, true);

            if (null === $themes) {
                WP_CLI::error('No themes found? Try `wp theme list` to check for errors');
                return;
            }

            switch ($this->outputType) {
                case self::OUTPUT_JSON:
                    break;
                case self::OUTPUT_NAGIOS:
                    break;
                default:
                    WP_CLI::line('');
                    WP_CLI::line('------------------------------');
                    WP_CLI::line('Checking theme vulnerabilities');
                    WP_CLI::line('------------------------------');
                    WP_CLI::line('');
                    WP_CLI::line('Vulnerabilities:');
                    break;
            }

            foreach ($themes as $theme) {
                $title = $theme['name'];
                $version = $theme['version'];

                $cache = WP_CLI::get_cache();
                $cache_key = sprintf("wp-sec/theme-%s-%s.json", $title, $version);
                $cache_file = $cache->has( $cache_key, $this->cacheTTL );

                if ($cache_file && $this->cached) {
                    $req = unserialize($cache->read($cache_key));
                    ++$this->cacheHitCount;
                }
                else {

                    if ($this->APIversion == self::API_V2) {
                        $url = sprintf('https://wpvulndb.com/api/v2/themes/%s', $title);
                        $req = WP_CLI\Utils\http_request('GET', $url);
                    } else {
                        $url = sprintf('https://wpvulndb.com/api/v3/themes/%s', $title);
                        $req = WP_CLI\Utils\http_request('GET', $url, null, array('Authorization' => sprintf('Token token=%s', $this->token)));
                    }

                    ++$this->vulndbRequestCount;

                    $cache->write($cache_key, serialize($req));
                }

                $json = json_decode($req->body, true);

                if ( $req->status_code  == '404') {
                    // For plugins we continue, because not every theme has a vulnerability and therfore no entry at wpvulndb.com
                    continue;
                } else if('20' != substr( $req->status_code, 0, 2 )) {
                    WP_CLI::error(sprintf('Couldn\'t check wpvulndb @ %s (HTTP code %s)', $url, $req->status_code));
                }

                $json_entry = NULL;
                foreach ($json as $entry_title => $entry) {
                    if (strtolower($title) == strtolower($entry_title)) {
                        $json_entry = $entry;
                        break;
                    }
                }
                if ($json_entry === NULL) {
                    WP_CLI::error(sprintf('Unexpected response from wpvulndb for theme %s', $title));
                }

                $vulnerabilities = $json_entry['vulnerabilities'];

                $themeVulnerabilities = array(
                    'title'   => $title,
                    'version' => $version,
                    'status'  => $theme['status'],
                    'details' => array(),
                    'count'   => 0
                );

                foreach ($vulnerabilities as $vulnerability) {
                    $safeVersion = $vulnerability['fixed_in'];

                    if (!$this->isVersionLessThan($version, $safeVersion)) {
                        continue;
                    }

                    ++$this->themeVulnerabilityCount;
                    ++$themeVulnerabilities['count'];
                    $themeVulnerabilities['details'][] = $vulnerability;

                    switch ($this->outputType) {
                        case self::OUTPUT_JSON:
                            break;
                        case self::OUTPUT_NAGIOS:
                            break;
                        default:
                            WP_CLI::line('-----------------------------');
                            WP_CLI::line(sprintf('Theme: %s', $title));
                            WP_CLI::line(sprintf('Version: %s', $version));
                            WP_CLI::line(sprintf('Vulnerability: %s', $vulnerability['title']));

                            if (array_key_exists('cve', $vulnerability['references'])) {
                                $cves = $vulnerability['references']['cve'];
                                WP_CLI::line(sprintf('CVE\'s: %s', implode(', ', $cves)));
                            }
                            WP_CLI::line(
                                sprintf(
                                    'Fixed in: %s',
                                    empty($vulnerability['fixed_in']) ? 'fix n/a' : $vulnerability['fixed_in']
                                )
                            );

                            break;
                    }
                }

                if ($themeVulnerabilities['count'] > 0) {
                    $this->themeVulnerabilities[] = $themeVulnerabilities;
                }

            }

            if ($this->themeVulnerabilityCount === 0) {
                switch ($this->outputType) {
                    case self::OUTPUT_JSON:
                        break;
                    case self::OUTPUT_NAGIOS:
                        break;
                    default:
                        WP_CLI::line('No known theme vulnerabilities found');
                        break;
                }
            }
        }

        /**
         * @param $versionToCheck
         * @param $minimumVersion
         *
         * @return bool
         */
        private function isVersionLessThan($versionToCheck, $minimumVersion)
        {
            $toCheckParts = explode('.', trim($versionToCheck));
            $minimumParts = explode('.', trim($minimumVersion));

            // Be sure to fill in zeros, e.g. we have 4.5 but fixed version is 4.5.3, so we modify 4.5 to 4.5.0
            if (count($minimumParts) > count($toCheckParts)) {
                $toCheckParts = array_pad($toCheckParts, count($minimumParts), 0);
            }

            // The other way around as well, in case we have 1.2.3 but fixed in is 1.2, we modify 1.2 to 1.2.0
            if (count($toCheckParts) > count($minimumParts)) {
                $minimumParts = array_pad($minimumParts, count($toCheckParts), 0);
            }

            foreach ($toCheckParts as $index => $version) {
                if ($version < $minimumParts[$index]) {
                    return true;
                } elseif ($version > $minimumParts[$index]) {
                    return false;
                }
            }

            return false; // equals to the minimum required version
        }
    }
}

if (!class_exists('WpSecVersion')) {
    class WpSecVersion
    {
        public function __invoke()
        {
            WP_CLI::line('Version: 1.0.0');
        }
    }
}

WP_CLI::add_command(
    'wp-sec check',
    'WpSecCheck',
    array(
        'shortdesc' => 'Checks for vulnerabilities at wpvulndb.com. See wp wp-sec check --help for more details',
        'synopsis' => array(
            array(
                'type' => 'assoc',
                'name' => 'type',
                'optional' => true,
                'default' => 'all',
                'options' => array('core', 'themes', 'plugins', 'all'),
            ),
            array(
                'type' => 'assoc',
                'name' => 'output',
                'optional' => true,
                'default' => 'user',
                'options' => array('json', 'nagios', 'user'),
            ),
            array(
                'type' => 'flag',
                'name' => 'cached',
                'optional' => true,
            ),
            array(
                'type' => 'assoc',
                'name' => 'ttl',
                'optional' => true
            ),
            array(
                'type' => 'assoc',
                'name' => 'api',
                'optional' => true
            ),
            array(
                'type' => 'assoc',
                'name' => 'token',
                'optional' => true
            ),
        ),
        'when' => 'before_wp_load',
    )
);

WP_CLI::add_command(
    'wp-sec version',
    'WpSecVersion',
    array(
        'shortdesc' => 'Returns current version of wp-sec',
        'when' => 'before_wp_load',
    )
);
