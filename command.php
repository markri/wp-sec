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
        private $outputType = true;
        private $cached = false;
        private $cacheTTL = null;

        private $coreVulnerabilityCount = 0;
        private $coreVulnerabilities = array();
        private $pluginVulnerabilityCount = 0;
        private $pluginVulnerabilities = array();
        private $themeVulnerabilityCount = 0;
        private $themeVulnerabilities = array();

        const OUTPUT_USER = 'user';
        const OUTPUT_JSON = 'json';
        const OUTPUT_NAGIOS = 'nagios';

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
            $this->cacheTTL = isset($assoc_args['ttl']) ? $assoc_args['ttl'] : 28800; // default to 8 hours

            // Validate wordpress installation
            $output = WP_CLI::launch_self('core is-installed', array(), array(), false, true);
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
                        WP_CLI::error(
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
                        WP_CLI::line('OK - no vulnerabilities found');
                        exit(0);
                    } else {
                        WP_CLI::line(
                            sprintf(
                                'CRITICAL - %s core, %s plugin and %s theme vulnerabilities found',
                                $this->coreVulnerabilityCount,
                                $this->pluginVulnerabilityCount,
                                $this->themeVulnerabilityCount
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

                    WP_CLI::line(json_encode($output));

                    break;
            }
        }

        /**
         * Checks core version at wpvulndb.
         */
        private function checkCoreVulnerability()
        {
            // Get version throug internal WP_CLI command
            $output = WP_CLI::launch_self('core version', array(), array(), false, true);
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
                $json = json_decode($cache->read($cache_key), true);
            }
            else {
                $url = sprintf('https://wpvulndb.com/api/v2/wordpresses/%s', $parameter);
                $req = WP_CLI\Utils\http_request('GET', $url);

                if ( 20 != substr( $req->status_code, 0, 2 ) ) {
                    WP_CLI::error(sprintf('Couldn\'t check wpvulndb @ %s (HTTP code %s)', $url, $req->status_code));
                }

                $cache->write($cache_key, $req->body);
                $json = json_decode($req->body, true);

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
            $output = WP_CLI::launch_self('plugin list', array(), array('format' => 'json'), false, true);
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
                $version = $plugin['version'];

                $cache = WP_CLI::get_cache();
                $cache_key = sprintf("wp-sec/plugin-%s-%s.json", $title, $version);
                $cache_file = $cache->has( $cache_key, $this->cacheTTL );

                if ($cache_file && $this->cached) {
                    $json = json_decode($cache->read($cache_key), true);
                }
                else {

                    $url = sprintf('https://wpvulndb.com/api/v2/plugins/%s', $title);
                    $req = WP_CLI\Utils\http_request('GET', $url);

                    if ( 20 != substr( $req->status_code, 0, 2 ) ) {
                      continue;
                    }

                    $cache->write($cache_key, $req->body);
                    $json = json_decode($req->body, true);

                }

                if (!array_key_exists($title, $json)) {
                    WP_CLI::error(sprintf('Unexpected response from wpvulndb for plugin %s', $title));
                }

                $vulnerabilities = $json[$title]['vulnerabilities'];
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
            $output = WP_CLI::launch_self('theme list', array(), array('format' => 'json'), false, true);
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
                    $json = json_decode($cache->read($cache_key), true);
                }
                else {

                    $url = sprintf('https://wpvulndb.com/api/v2/themes/%s', $title);
                    $req = WP_CLI\Utils\http_request('GET', $url);

                    if ( 20 != substr( $req->status_code, 0, 2 ) ) {
                      continue;
                    }

                    $cache->write($cache_key, $req->body);
                    $json = json_decode($req->body, true);

                }

                if (!array_key_exists($title, $json)) {
                    WP_CLI::error(sprintf('Unexpected response from wpvulndb for theme %s', $title));
                }

                $vulnerabilities = $json[$title]['vulnerabilities'];
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
            WP_CLI::line('Version: 0.0.2');
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
