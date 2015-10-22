import re
import idc
import idaapi
import idautils
import logging

class IDAEngine(object):
	"""
	
		Tested on IDA Pro v6.5
	"""
	#Specifies a 16bit segment
	SEG_16	=	0
	#Specifies a 32bit segment
	SEG_32	=	1
	#Specifies a 64bit segment
	SEG_64	=	2

	DEFAULT_SEGMENT_SIZE = SEG_16
	
	#Specifies a DATA segment
	SEG_DATA = "DATA"
	#Specifies a CODE segment
	SEG_CODE = "CODE"

	SEG_TYPE_CODE = 2
	SEG_TYPE_DATA = 3		
	
	FAIL = 0
	SUCCESS = 1

	logger = logging.getLogger(__name__)
	
	def IDAEngine(self):
		pass

	def make_comment(self, _ea, _comment):
		"""
		Creates a comment at the given address.
		
		@param _ea: The address where the comment will be created.
		@param _comment: The comment
		@return IDAEngine.SUCCESS if the comment as created successfully,
		IDAEngine.FAIL otherwise.
		"""	
		return idc.MakeComm(_ea, _comment)
		
	def make_repeat_comment(self, _ea, _comment):
		"""
		Creates a repeatable comment at the given address.
		
		@param _ea: The address where the comment will be created.
		@param _comment: The comment
		@return IDAEngine.SUCCESS if the comment as created successfully,
		IDAEngine.FAIL otherwise.
		"""	
		return idc.MakeRptCmt(_ea, _comment)

	def backup_database(self):
		""" 
			Backup the database to a file similar to 
			IDA's snapshot function. 
		"""
		time_string = strftime('%Y%m%d%H%M%S')
		file = idc.GetInputFile()
		if not file:
			raise NoInputFileException('No input file provided')
		input_file = rsplit(file, '.', 1)[0]
		backup_file = '%s_%s.idb' % (input_file, time_string)
		idc.SaveBase(backup_file, idaapi.DBFL_BAK)  
  
	def create_segment(self, _startea, _endea, _name, 
		_type, _segsize=DEFAULT_SEGMENT_SIZE):
		"""
			Creates a segment between provided addresses.
			
			@param _startea: The start address of the segment.
			@param _endea: The end address of the segment.
			@param _name: Name to be given to the new segment.
			@param _type: Either idaapi.SEG_CODE to specified a code
				segment or idaapi.SEG_DATA for a segment containing data.
			@param _segsize: Bitness of the segment, e.g. 16, 32 or 64 bit.
		"""		
		idc.AddSeg(_startea, _endea, 0, _segsize, 1, 2)
		idc.RenameSeg(_startea, _name) 
		idc.SetSegmentType(ScreenEA(), _type)
  
	def create_data_segment(self, _startea, _endea, _name,
		_segsize=DEFAULT_SEGMENT_SIZE):
		"""
			Wrapper around the create_segment function to 
			create a new data segment.
			@param _startea: The start address of the segment.
			@param _endea: The end address of the segment.
			@param _name: Name to be given to the new segment.
			@param _segsize: Bitness of the segment, e.g. 16, 32 or 64 bit.			
		"""		
		self.create_segment(_startea, _endea, _name, idaapi.SEG_DATA, _segsize)
	
	def create_code_segment(self, _startea, _endea, _name, 
		_segsize=DEFAULT_SEGMENT_SIZE):
		"""
			Wrapper around the create_segment function to 
			create a new code segment.
			@param _startea: The start address of the segment.
			@param _endea: The end address of the segment.
			@param _name: Name to be given to the new segment.
			@param _segsize: Bitness of the segment, e.g. 16, 32 or 64 bit.			
		"""			
		self.create_segment(_startea, _endea, _name, idaapi.SEG_CODE, _segsize)  
  
	def create_string_at(self, _startea, _unicode=False):
		terminator = "0000"
		strend = self.find_next_byte_string(_startea, terminator)
		if strend != idaapi.BADADDR:
			self.create_string(_startea, strend+1, _unicode)	
  
	def create_string(self, _startea, _endea, _segname=".const", _unicode=False):
		
		if (SegStart(_startea) == idc.BADADDR):
			self.create_data_segment(_startea, _endea, ".const")
		else:
			segtype = GetSegmentAttr(_startea, SEGATTR_TYPE)
			if (segtype != IDAEngine.SEG_TYPE_DATA):
				DelSeg(_startea, 0)
				self.create_data_segment(_startea, _endea, _segname)
		
		result = MakeStr(_startea, _endea)
		if (result == IDAEngine.FAIL):
			print "[-] Failed to create a string at 0x{:x} to 0x{:x}.".format(_startea, _endea)  
  
	def current_file_offset(self):
		return idaapi.get_fileregion_offset(ScreenEA())
	
	def min_file_offset(self):
		return idaapi.get_fileregion_offset(MinEA())

	def max_file_offset(self):
		return idaapi.get_fileregion_offset(MaxEA())  
  
	def get_byte_at(self, _ea):
		return idc.Byte(_ea)
  
	def get_word_at(self, _ea):
		return idc.Word(_ea)
  
	def get_dword_at(self, _ea):
		return idc.Dword(_ea)
  
	def get_all_strings(self, _filter='', 
		_encoding=(Strings.STR_UNICODE | Strings.STR_C)):
		"""
		Retrieves all strings from the current file matching the
		regular expression specified in the filter parameter. If no
		filter value is provided, all strings with the specified encoding
		are returned.
		
		Values for the _encoding parameters includes:
		- Strings.STR_UNICODE
		- Strings.STR_C
		
		Values for the _encoding parameter can be combined using the |
		operator. Example:
		
		_encoding=(Strings.STR_UNICODE | Strings.STR_C)
		
		@param _filter Regular expression to filter unneeded strings.
		@param _encoding Specified the type of strings to seek.
		@return A list of strings
		"""		
		strings = []
		string_finder = idautils.Strings(False)
		string_finder.setup(strtypes=_encoding)
		
		for index, string in enumerate(string_finder):
			if filter:
				if re.search(_filter, string):
					strings.append(string)
			else:
				strings.append(string)
		return strings
  
	def get_string_at(self, _ea):
		"""
		
		"""		
		stype = idc.GetStringType(_ea)
		return idc.GetString(_ea, strtype=stype)  
  
	def get_all_comments_at(self, _ea):
		"""
		Returns both normal and repeatable comments at
		the specified address. If both are present, a single
		string is returned, both comments separated by a semi-
		colon (:)
		
		@param _ea: Address from which to retrieve the comments
		@return: A string containing both normal and repeatable comments,
			or an empty string if no comments are found.
		"""	
		normal_comment = self.get_normal_comment(_ea)
		rpt_comment = self.get_repeat_comment(_ea)
		comment = normal_comment

		if (comment and rpt_comment):
			comment += ":" + rpt_command
		
		return comment
  
	def get_normal_comment_at(self, _ea):
		comment = idc.Comment(_ea)
		if not comment:
			comment = ""
		
		return comment;
  
	def get_repeat_comment(self, _ea):
		comment = idc.RptCmt(_ea)
		if not comment:
			comment = ""
		
		return comment;  

	def get_disasm(self, _ea):
		return idc.GetDisasm(_ea)
  
	def get_mnemonic(self, _ea):
		return idc.GetMnem(_ea)		
		
	def get_first_segment(self):
		"""
		Returns the address of the first defined 
		segment of the file.

		@return: Start address of the first segment or 
			idc.BADADDR if no segments are defined
		"""	
		return idc.FirstSeg()		
		
	def get_next_segment(self, _ea):
		"""
		Returns the address of the segment following the one defined 
		at the given address.

		@param _ea: Address of the current segment.
		
		@return: Start address of the next segment or 
			idc.BADADDR if no segments are defined
		"""	
		return idc.FirstSeg()			
		
	def get_segment_name(self, _ea):
		return idc.Segname(_ea)
		
	def get_segment_start(self, _ea):
		return idc.SegStart(_ea)
		
	def get_segment_end(self, _ea):
		return idc.SegEnd(_ea)	

	def find_next_byte_string(self, _startea, _bytestr, _fileOffset = False):
		offset = None
		ea = _startea;
		if ea == idaapi.BADADDR:
			print ("[-] Failed to retrieve starting address.")
			offset = None
		else:
			block = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, _bytestr, 16)
			if (block == idc.BADADDR):
				offset = None
			if _fileOffset:
				offset = idaapi.get_fileregion_offset(block)
			else:
				offset = block
		return offset
		
	def find_byte_string(self, _startea, _endea, _bytestr, 
		_fileOffsets = False, _showmsg = False):
		try:
			offsets = []
			ea = _startea;
			if ea == idaapi.BADADDR:
				print ("[-] Failed to retrieve starting address.")
				return None
			else:
				block = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, _bytestr, 16)
				if (block == idc.BADADDR):
					print("[-] Byte string '{:s}' not found.".format(_bytestr))
					
				while (block != idc.BADADDR and block < _endea):
					block_file_offset = idaapi.get_fileregion_offset(block)
					if _fileOffsets:
						offsets.append(block_file_offset)
					else:
						offsets.append(block)
					next_block_offset = idaapi.get_fileregion_ea(block_file_offset+4)
					if (_showmsg):
						print("[+] Byte string '{:s}' found at offset 0x{:X}, file offset 0x{:X}.".format(
							_bytestr,
							block,
							block_file_offset))
					block = FindBinary(next_block_offset, SEARCH_DOWN | SEARCH_CASE, _bytestr, 16)
				return offsets
		except Exception as e:
			print("[-] An error occured while seeking byte string {:s}: {:s}".format(_bytestr, e.message))
			return None
			
		
	def find_functions_ranges(self, _startea, _endea, _prolog, _epilog):
		functions = []
		prolog_offsets = self.find_byte_string(_startea, _endea, _prolog, False)
		for offset_idx in range(0, len(prolog_offsets)):
			epilog_offset = self.find_next_byte_string(
				prolog_offsets[offset_idx],
				_epilog)
			if epilog_offset != idc.BADADDR:
				functions.append((prolog_offsets[offset_idx], epilog_offset))
		return functions;

	def define_function(self, _startea, _endea):
		result = 0
		try:
			prev_seg_type = GetSegmentAttr(_startea-1, SEGATTR_TYPE)
		except:
			prev_seg_type = -1
			
		for ea in range(_startea, _endea):
			idc.DelSeg(ea, 0)
		
		if (prev_seg_type == IDAEngine.SEG_TYPE_CODE):
			prev_seg_start = SegStart(_startea-1)
			result = idc.SetSegBounds(_startea-1, prev_seg_start, _endea, 0)
		else:
			result = self.create_code_segment(_startea, _endea, ".text")
			
		if (result == IDAEngine.FAIL):
			print("[-] Failed to create code segment from 0x{:x} to 0x{:x}.".format(_startea, _endea))
			return IDAEngine.FAIL
		
		result = idc.MakeCode(_startea)
		result = idc.MakeFunction(_startea, _endea)
		
		for ea in range(_startea+1, _endea):
			result = idc.MakeCode(ea)
				
		return IDAEngine.SUCCESS

	def define_all_functions(self, _prolog, _epilog, _comments=None):
		startea = MinEA()
		endea = MaxEA()
		franges = self.find_functions_ranges(startea, endea, _prolog, _epilog)
		
		if franges:
			for (fstart, fend) in franges:
				result = self.define_function(fstart, fend+3);
				if result == IDAEngine.FAIL:
					print("[-] Failed to create function from 0x{:x} to 0x{:x}.".format(fstart, fend))
				if _comments != None:
					self.set_comments(fstart, fend, _comments)
		else:
			print("[-] No functions found.")
			return IDAEngine.FAIL
		
		return IDAEngine.SUCCESS
		
	def set_comments(self, _startea, _endea, _comments):
		for ea in range(_startea, _endea):
			try:
				asm = idc.GetDisasm(ea).lower()
				mne = idc.GetMnem(ea).lower()
				comment = ""
				if asm in _comments.keys():
					comment = _comments[asm]
				elif mne in _comments.keys():
					comment = _comments[mne]
					
				if comment: 
					self.make_comment(ea, comment)
			except Exception as e:
				print e.message
				
		return IDAEngine.SUCCESS