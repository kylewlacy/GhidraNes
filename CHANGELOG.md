# Changelog

## [v20250329] - 2025-03-29
### Changed
- Included an extension build for Ghidra v11.3.1. All versions of Ghidra from the last release are still supported as well

### Added
- Support for iNES mapper 4 / MMC3 ([#19](https://github.com/kylewlacy/GhidraNes/pull/19) by [@GrasonHumphrey](https://github.com/GrasonHumphrey))

## [v20240311] - 2024-03-11
### Changed
- Include multiple versions of Ghidra in the release (10.3 - 11.0.1). Thanks to [@antoniovazquezblanco](https://github.com/antoniovazquezblanco) for adding the CI pipeline to make this happen! ([#14](https://github.com/kylewlacy/GhidraNes/pull/14))

### Added

- Support for iNES mapper 2 / UxROM ([#13](https://github.com/kylewlacy/GhidraNes/pull/13) by [@victorsevero](https://github.com/victorsevero))
- Support for iNES mapper 10 / MMC4 ([#15](https://github.com/kylewlacy/GhidraNes/pull/15) by [@rsgrava](https://github.com/rsgrava))

## [v20230527-10.3] - 2023-05-27
### Added

- Initial support for AxROM mapper (iNES mapper 7) ([#10](https://github.com/kylewlacy/GhidraNes/pull/10) by [@CBongo](https://github.com/CBongo))

### Changed
- Upgraded from Ghidra 10.2.2 to 10.3
    - Updated help HTML to fix Gradle build when using Ghidra 10.3 ([#11](https://github.com/kylewlacy/GhidraNes/pull/11) by [@CBongo](https://github.com/CBongo))

## [v20221227-10.2.2] - 2022-12-27
### Added

- Initial support for iNES mapper 19 ([#8](https://github.com/kylewlacy/GhidraNes/pull/8) by [@Notify-ctrl](https://github.com/Notify-ctrl))

## [v20221127-10.2.2] - 2022-11-27
### Added
- Initial support for MMC1 mapper (iNES mapper 1) ([#7](https://github.com/kylewlacy/GhidraNes/pull/7) by [@Grazfather](https://github.com/Grazfather))

### Fixed
- Fixed magic number check for iNES 1.0 ROMs ([#5](https://github.com/kylewlacy/GhidraNes/pull/5) by [@Grazfather](https://github.com/Grazfather))

### Changed
- Added more register labels ([#6](https://github.com/kylewlacy/GhidraNes/pull/6) by @Grazfather)
- Upgraded from Ghidra 10.0.1 to 10.2.2 (other versions may still work, but are not officially supported)

## [v20210802-10.0.1] - 2021-08-02
### Changed
- Upgraded from Ghidra 9.1.2 to 10.0.1

## [v20200912-9.1.2] - 2020-09-12
### Added
- Initial release, including support for iNES 1.0 ROMs with NROM mappers (mapper 0)

[Unreleased]: https://github.com/kylewlacy/GhidraNes/compare/v20250329...HEAD
[v20250329]: https://github.com/kylewlacy/GhidraNes/releases/tag/v20250329
[v20240311]: https://github.com/kylewlacy/GhidraNes/releases/tag/v20240311
[v20230527-10.3]: https://github.com/kylewlacy/GhidraNes/releases/tag/v20230527-10.3
[v20221227-10.2.2]: https://github.com/kylewlacy/GhidraNes/releases/tag/v20221227-10.2.2
[v20221127-10.2.2]: https://github.com/kylewlacy/GhidraNes/releases/tag/v20221127-10.2.2
[v20210802-10.0.1]: https://github.com/kylewlacy/GhidraNes/releases/tag/v20210802-10.0.1
[v20200912-9.1.2]: https://github.com/kylewlacy/GhidraNes/releases/tag/v20200912-9.1.2
