/*
Copyright 2015 Jan Broer All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ipset is a library providing a wrapper to the IPtables ipset userspace utility
package ipset

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/go-semver/semver"
	log "github.com/sirupsen/logrus"
)

const (
	minIpsetVersion = "6.0.0"
	AllSets         = ""
)

var (
	ipsetPath            string
	errIpsetNotFound     = errors.New("Ipset utility not found")
	errIpsetNotSupported = errors.New("Ipset utility version is not supported, requiring version >= 6.0")
)

// Stats defines the type and metrics of the sets
type Stats struct {
	Type    string
	Size    uint64
	Refs    uint64
	Entries uint64
}

// Params defines optional parameters for creating a new set.
type Params struct {
	HashFamily string
	HashSize   int
	MaxElem    int
	Timeout    int
}

// IPSet implements an Interface to an set.
type IPSet struct {
	Name       string
	HashType   string
	HashFamily string
	HashSize   int
	MaxElem    int
	Timeout    int
}

func initCheck(name ...string) error {
	var checkname string
	if ipsetPath == "" {

		if len(name) == 0 || (len(name) == 1 && name[0] == "") {
			checkname = "ipset"
		} else {
			checkname = name[0]
		}

		path, err := exec.LookPath(checkname)
		if err != nil {
			return errIpsetNotFound
		}
		ipsetPath = path
		supportedVersion, err := getIpsetSupportedVersion()
		if err != nil {
			log.Warnf("Error checking ipset version, assuming version at least 6.0.0: %v", err)
			supportedVersion = true
		}
		if supportedVersion {
			return nil
		}
		return errIpsetNotSupported
	}
	return nil
}

func (s *IPSet) createHashSet(name string) error {
	/*	out, err := exec.Command("/usr/bin/sudo",
		ipsetPath, "create", name, s.HashType, "family", s.HashFamily, "hashsize", strconv.Itoa(s.HashSize),
		"maxelem", strconv.Itoa(s.MaxElem), "timeout", strconv.Itoa(s.Timeout), "-exist").CombinedOutput()*/
	out, err := exec.Command(ipsetPath, "create", name, s.HashType, "family", s.HashFamily, "hashsize", strconv.Itoa(s.HashSize),
		"maxelem", strconv.Itoa(s.MaxElem), "timeout", strconv.Itoa(s.Timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating ipset %s with type %s: %v (%s)", name, s.HashType, err, out)
	}
	/* do NOT flush existing ipset
	out, err = exec.Command(ipsetPath, "flush", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error flushing ipset %s: %v (%s)", name, err, out)
	}
	*/
	return nil
}

// Init sets up the package with the named ipset or default
func Init(name string) error {
	return initCheck(name)
}

// New creates a new set and returns an Interface to it.
// Example:
// 	testIpset := ipset.New("test", "hash:ip", &ipset.Params{})
func New(name string, hashtype string, p *Params) (*IPSet, error) {
	// Using the ipset utilities default values here
	if p.HashSize == 0 {
		p.HashSize = 1024
	}

	if p.MaxElem == 0 {
		p.MaxElem = 65536
	}

	if p.HashFamily == "" {
		p.HashFamily = "inet"
	}

	// Check if hashtype is a type of hash
	if !strings.HasPrefix(hashtype, "hash:") {
		return nil, fmt.Errorf("not a hash type: %s", hashtype)
	}

	if err := initCheck(); err != nil {
		return nil, err
	}

	s := IPSet{name, hashtype, p.HashFamily, p.HashSize, p.MaxElem, p.Timeout}
	err := s.createHashSet(name)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Refresh is used to to overwrite the set with the specified entries.
// The ipset is updated on the fly by hot swapping it with a temporary set.
func (s *IPSet) Refresh(entries []string) error {
	tempName := s.Name + "-temp"
	err := s.createHashSet(tempName)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		out, err := exec.Command(ipsetPath, "add", tempName, entry, "-exist").CombinedOutput()
		if err != nil {
			log.Errorf("error adding entry %s to set %s: %v (%s)", entry, tempName, err, out)
		}
	}
	err = Swap(tempName, s.Name)
	if err != nil {
		return err
	}
	err = destroyIPSet(tempName)
	if err != nil {
		return err
	}
	return nil
}

// Test is used to check whether the specified entry is in the set or not.
func (s *IPSet) Test(entry string) (bool, error) {
	out, err := exec.Command(ipsetPath, "test", s.Name, entry).CombinedOutput()
	if err == nil {
		reg, e := regexp.Compile("NOT")
		if e == nil && reg.MatchString(string(out)) {
			return false, nil
		} else if e == nil {
			return true, nil
		} else {
			return false, fmt.Errorf("error testing entry %s: %v", entry, e)
		}
	} else {
		return false, fmt.Errorf("error testing entry %s: %v (%s)", entry, err, out)
	}
}

// Add is used to add the specified entry to the set.
// A timeout of 0 means that the entry will be stored permanently in the set.
func (s *IPSet) Add(entry string, timeout int) error {
	out, err := exec.Command(ipsetPath, "add", s.Name, entry, "timeout", strconv.Itoa(timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error adding entry %s: %v (%s)", entry, err, out)
	}
	return nil
}

// AddOption is used to add the specified entry to the set.
// A timeout of 0 means that the entry will be stored permanently in the set.
func (s *IPSet) AddOption(entry string, option string, timeout int) error {
	out, err := exec.Command(ipsetPath, "add", s.Name, entry, option, "timeout", strconv.Itoa(timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error adding entry %s with option %s : %v (%s)", entry, option, err, out)
	}
	return nil
}

// Del is used to delete the specified entry from the set.
func (s *IPSet) Del(entry string) error {
	out, err := exec.Command(ipsetPath, "del", s.Name, entry, "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting entry %s: %v (%s)", entry, err, out)
	}
	return nil
}

// Flush is used to flush all entries in the set.
func (s *IPSet) Flush() error {
	out, err := exec.Command(ipsetPath, "flush", s.Name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error flushing set %s: %v (%s)", s.Name, err, out)
	}
	return nil
}

// List is used to show the contents of a set
func (s *IPSet) List() ([]string, error) {
	return list(s.Name)
}

// ListTerse is used to show the name and statistics for a set
func (s *IPSet) ListTerse() ([]string, error) {
	return listWithOpts(s.Name, "-t")
}

func (s *IPSet) Statistics() (stats Stats, err error) {
	info, err := s.ListTerse()
	if err != nil {
		return
	}
	if len(info) == 0 {
		return
	}
	// split on white spaces
	for _, l := range strings.Fields(info[0]) {
		// split on ":"
		values := strings.Split(l, ":")
		if len(values) == 0 {
			continue
		}
		switch values[0] {
		case "Type":
			stats.Type = values[2]
		case "Size in memory":
			stats.Size, err = strconv.ParseUint(values[2], 0, 64)
			if err != nil {
				return
			}
		case "References":
			stats.Refs, err = strconv.ParseUint(values[2], 0, 64)
			if err != nil {
				return
			}
		case "Number of entries":
			stats.Entries, err = strconv.ParseUint(values[2], 0, 64)
			if err != nil {
				return
			}
		}
	}
	return
}

// Destroy is used to destroy the set.
func (s *IPSet) Destroy() error {
	out, err := exec.Command(ipsetPath, "destroy", s.Name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error destroying set %s: %v (%s)", s.Name, err, out)
	}
	return nil
}

// DestroyAll is used to destroy the set.
// The prefix may be a prefix string or the constant ipset.AllSets
// to specify that all existing sets should be destroyed
// Note that attempting to destroy a set that is in use will
// result in an error being returned.
//
// I use the variadic form here to preserve the original API with no arguments.
// i.e. DestroyAll() with no arguments will still work.
//
// DestroyAll("") and DestroyAll(ipset.AllSets) are equivalent to DestroyAll()
//
// DestroyAll("prefix") is new functionality
// Note that the variadic allows for DestroyAll("prefix1", "prefix2")
// but all arguments after prefix1 are currently ignored
//
func DestroyAll(prefix string) error {

	initCheck()

	if prefix == "" {
		return exec.Command(ipsetPath, "destroy").Run()
	}

	ips, err := listAllSetNames()
	if err != nil {
		return err
	}

	var errs strings.Builder
	for _, name := range ips {
		if strings.HasPrefix(name, prefix) { // AllSets always matches :)
			if err = destroyIPSet(name); err != nil {
				errs.WriteString(fmt.Sprintf("ipset(%s): %s\n", name, err.Error()))
			}
		}
	}

	if len(errs.String()) != 0 { // if errors occured above
		prefixMsg := func() string {
			if prefix == AllSets {
				return "all"
			}
			return "prefix"
		}
		return fmt.Errorf("error destroying %s sets %s (%s)", prefixMsg(), prefix, errs.String())
	}

	return nil
}

// Swap is used to hot swap two sets on-the-fly. Use with names of existing sets of the same type.
func Swap(from, to string) error {
	out, err := exec.Command(ipsetPath, "swap", from, to).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error swapping ipset %s to %s: %v (%s)", from, to, err, out)
	}
	return nil
}

func destroyIPSet(name string) error {
	out, err := exec.Command(ipsetPath, "destroy", name).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "does not exist") {
		return fmt.Errorf("error destroying ipset %s: %v (%s)", name, err, out)
	}
	return nil
}

func list(set string) ([]string, error) {
	out, err := exec.Command(ipsetPath, "list", set).CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("error listing set %s: %v (%s)", set, err, out)
	}
	r := regexp.MustCompile("(?m)^(.*\n)*Members:\n")
	newlist := r.ReplaceAllString(string(out[:]), "")
	return strings.FieldsFunc(newlist, fieldsFunc), nil
}

func listWithOpts(set string, opts ...string) ([]string, error) {
	var cmd []string
	if len(opts) != 0 {
		cmd = append(cmd, opts...)
	}
	cmd = append(cmd, "list")
	cmd = append(cmd, set)
	out, err := exec.Command(ipsetPath, "list", set).CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("error listing set %s: %v (%s)", set, err, out)
	}
	r := regexp.MustCompile("(?m)^(.*\n)*Members:\n")
	newlist := r.ReplaceAllString(string(out[:]), "")
	return strings.FieldsFunc(newlist, fieldsFunc), nil
}

func getIpsetSupportedVersion() (bool, error) {
	minVersion, err := semver.NewVersion(minIpsetVersion)
	if err != nil {
		return false, err
	}
	// Returns "vX.Y".
	vstring, err := getIpsetVersionString()
	if err != nil {
		return false, err
	}
	// Make a dotted-tri format version string
	vstring = vstring + ".0"
	// Make a semver of the part after the v in "vX.X.X".
	version, err := semver.NewVersion(vstring[1:])
	if err != nil {
		return false, err
	}
	if version.LessThan(*minVersion) {
		return false, nil
	}
	return true, nil
}

func getIpsetVersionString() (string, error) {
	bytes, err := exec.Command(ipsetPath, "--version").CombinedOutput()
	if err != nil {
		return "", err
	}
	versionMatcher := regexp.MustCompile("v[0-9]+\\.[0-9]+")
	match := versionMatcher.FindStringSubmatch(string(bytes))
	if match == nil {
		return "", fmt.Errorf("no ipset version found in string: %s", bytes)
	}
	return match[0], nil
}

func listAllSetNames() ([]string, error) {
	out, err := exec.Command(ipsetPath, "list", "-n").CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("error listing all sets: %v (%s)", err, out)
	}
	return strings.FieldsFunc(string(out), fieldsFunc), nil
}

// use a fields function for strings.FieldsFunc() to skip all newlines and returns and thus
// eliminate the "" empty strings normally returned from strings.Split()
// on empty, blank lines or space filled field values
func fieldsFunc(c rune) bool {
	return c == '\n' || c == '\r' || c == ' ' || c == '\t'
}
