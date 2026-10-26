/**
 * Copyright (c) 2019-present Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package platform

// OSReleaseFixtures provides test fixtures for /etc/os-release parsing.
// These cover the major distributions: Debian, Ubuntu, Alpine, Fedora, RHEL, Rocky, Arch, openSUSE/SLES.
var OSReleaseFixtures = map[string]string{
	"debian": `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
ID_LIKE=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
`,
	"ubuntu": `PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
`,
	"alpine": `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.1
PRETTY_NAME="Alpine Linux v3.19"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
`,
	"fedora": `NAME="Fedora Linux"
VERSION="39 (Container Image)"
ID=fedora
VERSION_ID=39
VERSION_CODENAME=""
PLATFORM_ID="platform:f39"
PRETTY_NAME="Fedora Linux 39 (Container Image)"
ANSI_COLOR="0;38;2;60;110;180"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:39"
DEFAULT_HOSTNAME="fedora"
HOME_URL="https://fedoraproject.org/"
DOCUMENTATION_URL="https://docs.fedoraproject.org/en-US/fedora/f39/system-administrators-guide/"
SUPPORT_URL="https://ask.fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=39
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=39
`,
	"rhel": `NAME="Red Hat Enterprise Linux Server"
VERSION="9.3 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.3"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::server"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9"
BUG_REPORT_URL="https://bugzilla.redhat.com/"

REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 9"
REDHAT_BUGZILLA_PRODUCT_VERSION=9.3
REDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"
REDHAT_SUPPORT_PRODUCT_VERSION=9.3
`,
	"rocky": `NAME="Rocky Linux"
VERSION="9.3 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel fedora"
VERSION_ID="9.3"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"
ANSI_COLOR="0;32"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:rocky:rocky:9::baseos"
HOME_URL="https://rockylinux.org/"
BUG_REPORT_URL="https://bugs.rockylinux.org/"
ROCKY_SUPPORT_PRODUCT="Rocky-Linux-9"
ROCKY_SUPPORT_PRODUCT_VERSION="9.3"
REDHAT_SUPPORT_PRODUCT="Rocky Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="9.3"
`,
	"arch": `NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
PRETTY_NAME="Arch Linux"
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://archlinux.org/"
DOCUMENTATION_URL="https://wiki.archlinux.org/"
SUPPORT_URL="https://bbs.archlinux.org/"
BUG_REPORT_URL="https://gitlab.archlinux.org/groups/archlinux/packaging/-/issues"
LOGO=archlinux-logo
`,
	"opensuse": `NAME="openSUSE Leap"
VERSION="15.5"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.5"
PRETTY_NAME="openSUSE Leap 15.5"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.5"
BUG_REPORT_URL="https://bugs.opensuse.org"
HOME_URL="https://www.opensuse.org/"
DOCUMENTATION_URL="https://en.opensuse.org/Portal:Leap"
LOGO="distributor-logo-Leap"
`,
	"sles": `NAME="SLES"
VERSION="15-SP5"
VERSION_ID="15.5"
ID="sles"
ID_LIKE="suse"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP5"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sles:15:sp5"
DOCUMENTATION_URL="https://documentation.suse.com/"
`,
}

// DarwinHostFixture provides a macOS Host for testing.
var DarwinHostFixture = Host{
	OS:      "darwin",
	Arch:    "arm64",
	HasTTY:  true,
	IsRoot:  false,
	HasSudo: true,
	Home:    "/Users/test",
}

// LinuxHostFixtures provides Linux Host fixtures for testing.
var LinuxHostFixtures = map[string]Host{
	"debian": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "debian",
			IDLike:  "debian",
			Version: "12",
		},
		Family: FamilyDebian,
		Home:   "/home/test",
	},
	"ubuntu": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "ubuntu",
			IDLike:  "debian",
			Version: "22.04",
		},
		Family: FamilyDebian,
		Home:   "/home/test",
	},
	"alpine": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "alpine",
			IDLike:  "",
			Version: "3.19.1",
		},
		Family: FamilyAlpine,
		Home:   "/home/test",
	},
	"fedora": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "fedora",
			IDLike:  "",
			Version: "39",
		},
		Family: FamilyRedHat,
		Home:   "/home/test",
	},
	"rhel": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "rhel",
			IDLike:  "fedora",
			Version: "9.3",
		},
		Family: FamilyRedHat,
		Home:   "/home/test",
	},
	"rocky": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "rocky",
			IDLike:  "rhel fedora",
			Version: "9.3",
		},
		Family: FamilyRedHat,
		Home:   "/home/test",
	},
	"arch": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "arch",
			IDLike:  "",
			Version: "",
		},
		Family: FamilyArch,
		Home:   "/home/test",
	},
	"opensuse": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "opensuse-leap",
			IDLike:  "suse opensuse",
			Version: "15.5",
		},
		Family: FamilySUSE,
		Home:   "/home/test",
	},
	"sles": {
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: Distro{
			ID:      "sles",
			IDLike:  "suse",
			Version: "15.5",
		},
		Family: FamilySUSE,
		Home:   "/home/test",
	},
}
