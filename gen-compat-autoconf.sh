#! /bin/sh

set -e

TARGET=${1:="compat-autoconf.h"}
TMP="${TARGET}.tmp"

rm -f "${TMP}"
touch "${TMP}"

gen_config() {
	KEY="${1}"
	VALUE="${2}"

	echo "#undef ${KEY}"
	echo "#undef __enabled_${KEY}"
	echo "#undef __enabled_${KEY}_MODULE"
	case "${VALUE}" in
	y)
		echo "#define ${KEY} 1"
		echo "#define __enabled_${KEY} 1"
		echo "#define __enabled_${KEY}_MODULE 0"
		;;
	m)
		echo "#define ${KEY} 1"
		echo "#define __enabled_${KEY} 0"
		echo "#define __enabled_${KEY}_MODULE 1"
		;;
	n)
		echo "#define __enabled_${KEY} 0"
		echo "#define __enabled_${KEY}_MODULE 0"
		;;
	*)
		echo "#define ${KEY} \"${VALUE}\""
		;;
	esac
}

# write config variables
gen_config 'CONFIG_BATMAN_ADV_LEGACY_DEBUG' ${CONFIG_BATMAN_ADV_LEGACY_DEBUG:="n"} >> "${TMP}"
gen_config 'CONFIG_BATMAN_ADV_LEGACY_BLA' ${CONFIG_BATMAN_ADV_LEGACY_BLA:="y"} >> "${TMP}"
gen_config 'CONFIG_BATMAN_ADV_LEGACY_DAT' ${CONFIG_BATMAN_ADV_LEGACY_DAT:="y"} >> "${TMP}"
gen_config 'CONFIG_BATMAN_ADV_LEGACY_NC' ${CONFIG_BATMAN_ADV_LEGACY_NC:="n"} >> "${TMP}"

# only regenerate compat-autoconf.h when config was changed
diff "${TMP}" "${TARGET}" > /dev/null 2>&1 || cp "${TMP}" "${TARGET}"
