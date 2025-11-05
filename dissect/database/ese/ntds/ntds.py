from __future__ import annotations

import logging
from functools import lru_cache, partial
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from dissect.database.ese.record import Record


from dissect.util.ldap import LogicalOperator, SearchFilter
from dissect.util.sid import read_sid
from dissect.util.ts import wintimestamp

from dissect.database.ese import ESE
from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.objects import OBJECTCLASS_MAPPING, Computer, Group, Object, User
from dissect.database.ese.ntds.secd import ACL, SecurityDescriptor
from dissect.database.ese.ntds.utils import (
    ATTRIBUTE_NORMALIZERS,
    FIXED_ATTR_COLS,
    FIXED_OBJ_MAP,
    OID_TO_TYPE,
    REVERSE_SPECIAL_ATTRIBUTE_MAPPING,
    convert_attrtyp_to_oid,
    increment_last_char,
    write_sid,
)

log = logging.getLogger(__name__)


class SchemaEntry(NamedTuple):
    dnt: int
    oid: str
    attrtyp: int
    ldap_name: str
    column_name: str | None = None
    type_oid: str | None = None
    link_id: int | None = None
    is_class: bool = False


class SchemaIndex:
    """A unified index for schema entries providing fast lookups by various keys.

    Provides efficient lookups for schema entries by DNT, OID, ATTRTYP,
    LDAP display name, and column name.
    """

    def __init__(self):
        """Initialize the schema index with empty collections."""
        self._entries: list[SchemaEntry] = []
        self._entry_count: int = 0
        self._dnt_index: dict[int, int] = {}
        self._oid_index: dict[str, int] = {}
        self._attrtyp_index: dict[int, int] = {}
        self._ldap_name_index: dict[str, int] = {}
        self._column_name_index: dict[str, int] = {}

    def _add_entry(self, entry: SchemaEntry) -> None:
        entry_index = self._entry_count
        self._entries.append(entry)
        self._entry_count += 1
        self._dnt_index[entry.dnt] = entry_index
        self._oid_index[entry.oid] = entry_index
        self._attrtyp_index[entry.attrtyp] = entry_index
        self._ldap_name_index[entry.ldap_name] = entry_index
        if entry.column_name:
            self._column_name_index[entry.column_name] = entry_index

    def lookup(self, **kwargs) -> SchemaEntry | None:
        """Lookup a schema entry by any indexed field.

        Supported keys: dnt, oid, attrtyp, ldap_name and column_name.

        Args:
            **kwargs: Exactly one keyword argument specifying the lookup key and value.

        Returns:
            The matching schema entry or None if not found.

        Raises:
            ValueError: If not exactly one lookup key is provided or if the key is unsupported.
        """
        if len(kwargs) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        ((key, value),) = kwargs.items()

        try:
            index = getattr(self, f"_{key}_index")
        except AttributeError:
            raise ValueError(f"Unsupported lookup key: {key}")

        idx = index.get(value)
        if idx is not None:
            return self._entries[idx]
        return None


class NTDS:
    """NTDS.dit Active Directory database parser.

    Provides methods to query and extract data from an NTDS.dit file,
    including users, computers, groups, and their relationships.

    Args:
        fh: A binary file handle to the NTDS.dit database file.
    """

    def __init__(self, fh: BinaryIO):
        self.db = ESE(fh)
        self.data_table = self.db.table("datatable")
        self.sd_table = self.db.table("sd_table")
        self.link_table = self.db.table("link_table")

        # Create the unified schema index
        self.schema_index = self._bootstrap_schema()

        # To be used when parsing LDAP queries into ESE-compatible data types
        self.TYPE_OID_ENCODE_FUNC = {
            "2.5.5.1": self._ldapDisplayName_to_DNT,  # Object(DN-DN); The fully qualified name of an object
            "2.5.5.2": self._oid_string_to_attrtyp,  # String(Object-Identifier); The object identifier
            "2.5.5.8": bool,  # Boolean; TRUE or FALSE values
            "2.5.5.9": int,  # Integer, Enumeration; A 32-bit number or enumeration
            "2.5.5.17": write_sid,  # String(Sid); Security identifier (SID)
        }

        # Used to parse the raw values from the database into Python objects
        self.TYPE_OID_DECODE_FUNC = {
            "2.5.5.1": self._DNT_to_ldapDisplayName,  # Object(DN-DN); The fully qualified name of an object
            "2.5.5.2": lambda attrtyp: self.schema_index.lookup(attrtyp=attrtyp).ldap_name,
            # String(Object-Identifier); The object identifier
            "2.5.5.3": str,
            "2.5.5.4": str,
            "2.5.5.5": str,
            "2.5.5.6": str,  # String(Numeric); A sequence of digits
            "2.5.5.7": None,  # TODO: Object(DN-Binary); A distinguished name plus a binary large object
            "2.5.5.8": bool,  # Boolean; TRUE or FALSE values
            "2.5.5.9": int,  # Integer, Enumeration; A 32-bit number or enumeration
            "2.5.5.10": bytes,  # String(Octet); A string of bytes
            "2.5.5.11": lambda t: wintimestamp(t * 10000000),
            "2.5.5.12": str,  # String(Unicode); A Unicode string
            "2.5.5.13": None,  # TODO: Object(Presentation-Address); Presentation address
            "2.5.5.14": None,  # TODO: Object(DN-String); A DN-String plus a Unicode string
            "2.5.5.15": partial(int.from_bytes, byteorder="little"),  # NTSecurityDescriptor; A security descriptor
            "2.5.5.16": int,  # LargeInteger; A 64-bit number
            "2.5.5.17": partial(read_sid, swap_last=True),  # String(Sid); Security identifier (SID)
        }

        # Cache frequently used and "expensive" methods
        self._construct_dn_cached = lru_cache(4096)(self._construct_dn_cached)
        self._DNT_lookup = lru_cache(4096)(self._DNT_lookup)
        self._get_attribute_converter = lru_cache(4096)(self._get_attribute_converter)

    def _oid_string_to_attrtyp(self, value: str) -> int | None:
        """Convert OID string or LDAP display name to ATTRTYP value.

        Supports both formats:
            objectClass=person       (LDAP display name)
            objectClass=2.5.6.6      (OID string)

        Args:
            value: Either an OID string (contains dots) or LDAP display name.

        Returns:
            ATTRTYP integer value or None if not found.
        """
        entry = self.schema_index.lookup(oid=value) if "." in value else self.schema_index.lookup(ldap_name=value)
        return entry.attrtyp if entry else None

    def _construct_dn_cached(self, dnt: int) -> str:
        """Construct Distinguished Name (DN) from a DNT value.

        This method walks up the parent hierarchy to build the full DN path.

        Args:
            dnt: The Directory Number Tag to construct the DN for.

        Returns:
            The fully qualified Distinguished Name as a string.

        Raises:
            ValueError: If the 'name' column cannot be found in schema.
        """
        current_record = self._DNT_lookup(dnt)

        name_column = self.schema_index.lookup(ldap_name="name").column_name
        if not name_column:
            raise ValueError("Unable to find 'name' column in schema")

        components = []

        while True:
            current_dnt = current_record.get(FIXED_ATTR_COLS["DNT"])
            if current_dnt in {0, 2}:  # Root object
                break

            pdnt = current_record.get(FIXED_ATTR_COLS["Pdnt"])
            if pdnt is None:
                break

            rdn_type = current_record.get(FIXED_ATTR_COLS["RdnType"])
            rdn_key = self.schema_index.lookup(attrtyp=rdn_type).ldap_name
            rdn_value = current_record.get(name_column)

            if rdn_key and rdn_value:
                components.append(f"{rdn_key}={rdn_value}".upper())

            # Move to parent
            current_record = self._DNT_lookup(pdnt)

        return ",".join(components)

    def _record_to_object(self, record: Record) -> Object:
        """Convert a database record to a properly typed Object instance.

        Args:
            record: The raw database record to convert.

        Returns:
            An Object instance, potentially cast to a more specific type
            (User, Computer, Group) based on objectClass.
        """
        obj = self._create_mapped_object(record)
        self._normalize_attribute_values(obj)
        return self._cast_to_specific_type(obj)

    def _create_mapped_object(self, record: Record) -> Object:
        """Create an Object with column names mapped to LDAP attribute names.

        Args:
            record: The database record to map.

        Returns:
            An Object with LDAP attribute names as keys.
        """
        mapped_record = {}

        for k, v in record.as_dict().items():
            schema_entry = self.schema_index.lookup(column_name=k)
            mapped_name = schema_entry.ldap_name if schema_entry else REVERSE_SPECIAL_ATTRIBUTE_MAPPING.get(k, k)
            mapped_record[mapped_name] = v

        return Object(mapped_record, ntds=self)

    def _normalize_attribute_values(self, obj: Object) -> None:
        """Convert attribute values to their proper Python types in-place.

        Args:
            obj: The Object to normalize attribute values for.
        """
        for attribute, value in obj.record.items():
            func = self._get_attribute_converter(attribute)
            if func:
                obj.record[attribute] = self._apply_converter(func, value)

    def _get_attribute_converter(self, attribute: str) -> Callable | None:
        """Get the appropriate converter function for an attribute.

        Args:
            attribute: The LDAP attribute name.

        Returns:
            A converter function or None if no converter is needed.
        """
        # First check the list of deviations
        func = ATTRIBUTE_NORMALIZERS.get(attribute)
        if func:
            return func

        # Next, try it using the regular TYPE_OID_DECODE_FUNC mapping
        attr_entry = self.schema_index.lookup(ldap_name=attribute)
        if attr_entry and attr_entry.type_oid:
            return self.TYPE_OID_DECODE_FUNC.get(attr_entry.type_oid)

        return None

    def _apply_converter(self, func: Callable, value: Any) -> Any:
        """Apply converter function to value(s), handling both single values and lists.

        Args:
            func: The converter function to apply.
            value: The value or list of values to convert.

        Returns:
            The converted value or list of converted values.
        """
        if isinstance(value, list):
            return [func(v) for v in value]
        return func(value)

    def _cast_to_specific_type(self, obj: Object) -> Object:
        """Cast generic Object to a more specific type based on objectClass.

        Args:
            obj: The generic Object to potentially cast.

        Returns:
            A more specific Object type (User, Computer, Group) if applicable,
            otherwise the original Object.
        """
        for class_name, cls in OBJECTCLASS_MAPPING.items():
            if class_name in obj.objectClass:
                return cls(obj)
        return obj

    def _bootstrap_schema(self) -> SchemaIndex:
        """Load the classes and attributes from the Schema into a unified index.

        Provides O(1) lookups for DNT, OID, ATTRTYP, Column, and LDAP display names.

        Returns:
            A SchemaIndex containing all schema entries from the database.
        """
        # Hardcoded index
        cursor = self.data_table.index("INDEX_00000000").cursor()
        schema_index = SchemaIndex()

        # Load objectClasses (e.g. "person", "user", "group", etc.)
        for record in cursor.find_all(**{FIXED_ATTR_COLS["objectClass"]: FIXED_OBJ_MAP["classSchema"]}):
            ldap_name = record.get(FIXED_ATTR_COLS["lDAPDisplayName"])
            attrtyp = int(record.get(FIXED_ATTR_COLS["governsID"]))
            oid = convert_attrtyp_to_oid(attrtyp)
            dnt = record.get(FIXED_ATTR_COLS["DNT"])

            schema_index._add_entry(SchemaEntry(dnt=dnt, oid=oid, attrtyp=attrtyp, ldap_name=ldap_name, is_class=True))

        # Load attributes (e.g. "cn", "sAMAccountName", "memberOf", etc.)
        for record in cursor.find_all(**{FIXED_ATTR_COLS["objectClass"]: FIXED_OBJ_MAP["attributeSchema"]}):
            attrtyp = record.get(FIXED_ATTR_COLS["attributeID"])
            type_oid = convert_attrtyp_to_oid(record.get(FIXED_ATTR_COLS["attributeSyntax"]))
            linkId = record.get(FIXED_ATTR_COLS["linkId"])
            if linkId is not None:
                linkId = linkId // 2

            ldap_name = record.get(FIXED_ATTR_COLS["lDAPDisplayName"])
            column_name = f"ATT{OID_TO_TYPE[type_oid]}{attrtyp}"
            oid = convert_attrtyp_to_oid(attrtyp)
            dnt = record.get(FIXED_ATTR_COLS["DNT"])

            schema_index._add_entry(
                SchemaEntry(
                    dnt=dnt,
                    oid=oid,
                    attrtyp=attrtyp,
                    ldap_name=ldap_name,
                    column_name=column_name,
                    type_oid=type_oid,
                    link_id=linkId,
                    is_class=False,
                )
            )

        return schema_index

    def _ldapDisplayName_to_DNT(self, ldapDisplayName: str) -> int | None:
        """Convert an LDAP display name to its corresponding DNT value.

        Args:
            ldapDisplayName: The LDAP display name to look up.

        Returns:
            The DNT value or None if not found.
        """
        entry = self.schema_index.lookup(ldap_name=ldapDisplayName)
        if entry:
            return entry.dnt
        return None

    def _DNT_to_ldapDisplayName(self, dnt: int) -> str | None:
        """Convert a DNT value to its corresponding LDAP display name.

        Args:
            dnt: The Directory Number Tag to look up.

        Returns:
            The LDAP display name or None if not found.
        """
        entry = self.schema_index.lookup(dnt=dnt)
        if entry:
            return entry.ldap_name
        return None

    def _DNT_lookup(self, dnt: int) -> Record:
        """Lookup a record by its DNT value.

        Args:
            dnt: The Directory Number Tag to look up.

        Returns:
            The database record for the given DNT.
        """
        return self.data_table.index("DNT_index").cursor().find(**{FIXED_ATTR_COLS["DNT"]: dnt})

    def _encode_value(self, attribute: str, value: str) -> int | bytes | str:
        """Encode a string value according to the attribute's type.

        Args:
            attribute: The LDAP attribute name.
            value: The string value to encode.

        Returns:
            The encoded value in the appropriate type for the attribute.
        """
        attr_entry = self.schema_index.lookup(ldap_name=attribute)
        if not attr_entry:
            return value

        attribute_type_OID = attr_entry.type_oid
        func = self.TYPE_OID_ENCODE_FUNC.get(attribute_type_OID)
        if func:
            return func(value)
        return value

    def _process_query(self, ldap: SearchFilter, passed_objects: None | list[Record] = None) -> Generator[Record]:
        """Process LDAP query recursively, handling nested logical operations.

        Args:
            ldap: The LDAP search filter to process.
            passed_objects: Optional list of records to filter instead of querying database.

        Yields:
            Records matching the search filter.
        """
        if not ldap.is_nested():
            if passed_objects is None:
                try:
                    yield from self._query_database(ldap)
                except IndexError:
                    log.debug("No records found for filter: %s", ldap)
            else:
                yield from self._filter_records(ldap, passed_objects)
            return

        if ldap.operator == LogicalOperator.AND:
            yield from self._process_and_operation(ldap, passed_objects)
        elif ldap.operator == LogicalOperator.OR:
            yield from self._process_or_operation(ldap, passed_objects)

    def _filter_records(self, ldap: SearchFilter, records: list[Record]) -> Generator[Record]:
        """Filter a list of records against a simple LDAP filter.

        Args:
            ldap: The LDAP search filter to apply.
            records: The list of records to filter.

        Yields:
            Records that match the filter criteria.
        """
        encoded_value = self._encode_value(ldap.attribute, ldap.value)
        attr_entry = self.schema_index.lookup(ldap_name=ldap.attribute)

        if not attr_entry or not attr_entry.column_name:
            return

        column_name = attr_entry.column_name
        has_wildcard = "*" in ldap.value
        wildcard_prefix = ldap.value.replace("*", "").lower() if has_wildcard else None

        for record in records:
            record_value = record.get(column_name)

            if self._value_matches_filter(record_value, encoded_value, has_wildcard, wildcard_prefix):
                yield record

    def _value_matches_filter(
        self, record_value: Any, encoded_value: Any, has_wildcard: bool, wildcard_prefix: str | None
    ) -> bool:
        """Check if a record value matches the filter criteria.

        Args:
            record_value: The value from the database record.
            encoded_value: The encoded filter value to match against.
            has_wildcard: Whether the filter contains wildcard characters.
            wildcard_prefix: The prefix to match for wildcard searches.

        Returns:
            True if the value matches the filter criteria.
        """
        if isinstance(record_value, list):
            return encoded_value in record_value

        if has_wildcard and wildcard_prefix and isinstance(record_value, str):
            return record_value.lower().startswith(wildcard_prefix)

        return encoded_value == record_value

    def _process_and_operation(self, ldap: SearchFilter, passed_objects: None | list[Record]) -> Generator[Record]:
        """Process AND logical operation.

        Args:
            ldap: The LDAP search filter with AND operator.
            passed_objects: Optional list of records to filter.

        Yields:
            Records matching all conditions in the AND operation.
        """
        if passed_objects is not None:
            records_to_process = passed_objects
            children_to_check = ldap.children
        else:
            # Use the first child as base query, then filter with remaining children
            base_query, *remaining_children = ldap.children
            records_to_process = list(self._process_query(base_query))
            children_to_check = remaining_children

        for record in records_to_process:
            if all(any(self._process_query(child, passed_objects=[record])) for child in children_to_check):
                yield record

    def _process_or_operation(self, ldap: SearchFilter, passed_objects: None | list[Record]) -> Generator[Record]:
        """Process OR logical operation.

        Args:
            ldap: The LDAP search filter with OR operator.
            passed_objects: Optional list of records to filter.

        Yields:
            Records matching any condition in the OR operation.
        """
        for child in ldap.children:
            yield from self._process_query(child, passed_objects=passed_objects)

    def _query_database(self, filter: SearchFilter) -> Generator[Record]:
        """Execute a simple LDAP filter against the database.

        Args:
            filter: The LDAP search filter to execute.

        Yields:
            Records matching the filter.

        Raises:
            ValueError: If the attribute is not found or has no column mapping.
        """
        # Validate attribute exists and get column mapping
        attr_entry = self.schema_index.lookup(ldap_name=filter.attribute)
        if not attr_entry:
            raise ValueError(f"Attribute '{filter.attribute}' not found in the NTDS database.")

        column_name = attr_entry.column_name
        if not column_name:
            raise ValueError(f"No column mapping found for attribute '{filter.attribute}'.")

        # Get the database index for this attribute
        index = self.data_table.find_index(column_name)
        if not index:
            raise ValueError(f"Index for attribute '{column_name}' not found in the NTDS database.")

        # Handle wildcard searches differently
        if "*" in filter.value and filter.value.endswith("*"):
            yield from self._handle_wildcard_query(index, column_name, filter.value)
        else:
            # Exact match query
            encoded_value = self._encode_value(filter.attribute, filter.value)
            cursor = index.cursor()
            try:
                yield from cursor.find_all(**{column_name: encoded_value})
            except KeyNotFoundError:
                log.debug("No record found for filter: %s", filter)

    def _handle_wildcard_query(self, index: Any, column_name: str, filter_value: str) -> Generator[Record]:
        """Handle wildcard queries using range searches.

        Args:
            index: The database index to search.
            column_name: The column name for the search.
            filter_value: The filter value containing wildcards.

        Yields:
            Records matching the wildcard pattern.
        """
        cursor = index.cursor()

        # Create search bounds
        value = filter_value.replace("*", "")
        cursor.seek(**{column_name: increment_last_char(value)})
        end_record = cursor.record()

        # Seek back to the start
        cursor.reset()
        cursor.seek(**{column_name: value})

        # Yield all records in range
        current_record = cursor.record()
        while current_record != end_record:
            yield current_record
            cursor.next()
            current_record = cursor.record()

    def get_members_from_group(self, group: Group) -> Generator[User]:
        """Get all users that are members of the specified group.

        Args:
            group: The Group object to get members for.

        Yields:
            User objects that are members of the group.

        Raises:
            TypeError: If the provided object is not a Group instance.
        """
        if not isinstance(group, Group):
            raise TypeError("The provided object is not a Group instance.")
        dnt_index = self.data_table.find_index(FIXED_ATTR_COLS["DNT"])
        dnt_cursor = dnt_index.cursor()

        link_index = self.link_table.index("link_index")
        link_cursor = link_index.cursor()
        link_cursor.seek(link_DNT=group.DNT)

        while link_cursor.record().get("link_DNT") == group.DNT:
            user_DNT = link_cursor.record().get("backlink_DNT")
            user = dnt_cursor.find(DNT_col=user_DNT)
            dnt_cursor.reset()
            yield self._record_to_object(user)
            link_cursor.next()

        # We also need to include users with primaryGroupID matching the group's RID
        primary_group_rid = group.objectSid.rsplit("-", 1)[1]
        if primary_group_rid is not None:
            yield from self.lookup(primaryGroupID=primary_group_rid)

    def get_groups_for_member(self, user: User) -> Generator[Group]:
        """Get all groups that the specified user is a member of.

        Args:
            user: The User object to get group memberships for.

        Yields:
            Group objects that the user is a member of.

        Raises:
            TypeError: If the provided object is not a User instance.
        """
        if not isinstance(user, User):
            raise TypeError("The provided object is not a User instance.")
        group_index = self.data_table.find_index(FIXED_ATTR_COLS["DNT"])
        group_cursor = group_index.cursor()

        backlink_index = self.link_table.index("backlink_index")
        backlink_cursor = backlink_index.cursor()
        backlink_cursor.seek(backlink_DNT=user.DNT)

        while backlink_cursor.record().get("backlink_DNT") == user.DNT:
            group_DNT = backlink_cursor.record().get("link_DNT")
            group = group_cursor.find(DNT_col=group_DNT)
            group_cursor.reset()
            yield self._record_to_object(group)
            backlink_cursor.next()

        # We also need to include the group with primaryGroupID matching the user's primaryGroupID
        primary_group_id = user.primaryGroupID
        if primary_group_id is not None:
            yield from self.lookup(objectSid=f"{user.objectSid.rsplit('-', 1)[0]}-{primary_group_id}")

    def construct_distinguished_name(self, record: Record) -> str | None:
        """Construct the Distinguished Name (DN) for a given record.

        Args:
            record: The database record to construct DN for.

        Returns:
            The fully qualified Distinguished Name or None if DNT is not available.
        """
        dnt = record.get("DNT")
        if dnt:
            return self._construct_dn_cached(dnt)
        return None

    def dacl(self, obj: Object) -> ACL | None:
        """Get the Discretionary Access Control List (DACL) for an object.

        Args:
            obj: The Object to retrieve the DACL for.

        Returns:
            The ACL object containing access control entries, or None if unavailable.
        """
        nt_security_descriptor = obj.record.get("nTSecurityDescriptor")
        if not nt_security_descriptor:
            return None

        try:
            # Get the SecurityDescriptor from the sd_table
            sd_index = self.sd_table.index("sd_id_index")
            sd_cursor = sd_index.cursor()
            sd_record = sd_cursor.find(sd_id=nt_security_descriptor)

            if not sd_record:
                return None

            sd_value = sd_record.get("sd_value")
            if not sd_value:
                return None

            security_descriptor = SecurityDescriptor(BytesIO(sd_value))
        except Exception:
            log.warning("Failed to parse security descriptor for object: %s", obj)
            return None
        else:
            return security_descriptor.dacl

    def query(self, query: str, optimize: bool = True) -> Generator[Object]:
        """Execute an LDAP query against the NTDS database.

        Args:
            query: The LDAP query string to execute.
            optimize: Whether to optimize the query (default: True).

        Yields:
            Object instances matching the query. Objects are cast to more specific
            types (User, Computer, Group) when possible.
        """
        ldap: SearchFilter = SearchFilter.parse(query, optimize)
        for record in self._process_query(ldap):
            yield self._record_to_object(record)

    def lookup(self, **kwargs: str) -> Generator[Object]:
        """Perform a simple attribute-value lookup query.

        Args:
            **kwargs: Exactly one keyword argument specifying attribute and value.

        Yields:
            Object instances matching the attribute-value pair.

        Raises:
            ValueError: If not exactly one attribute is provided.
        """
        if len(kwargs) != 1:
            raise ValueError("Exactly one attribute must be provided")

        ((attr, value),) = kwargs.items()
        yield from self.query(f"({attr}={value})")

    def users(self) -> Generator[User]:
        """Get all user objects from the database.

        Yields:
            User objects representing all users in the directory.
        """
        yield from self.lookup(objectCategory="person")

    def computers(self) -> Generator[Computer]:
        """Get all computer objects from the database.

        Yields:
            Computer objects representing all computers in the directory.
        """
        yield from self.lookup(objectCategory="computer")

    def groups(self) -> Generator[Group]:
        """Get all group objects from the database.

        Yields:
            Group objects representing all groups in the directory.
        """
        yield from self.lookup(objectCategory="group")
