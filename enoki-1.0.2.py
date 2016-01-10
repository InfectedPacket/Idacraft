#!/usr/bin/env python
# Copyright (C) 2015 Jonathan Racicot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
#
# If you use this program and find it useful, please include a link
# or reference to the project's page in your program and/or document.
#
# Reference (Chicago):
#  Racicot, Jonathan. 2016. Enoki (version 1.0.2). Windows/Mac/Linux. Ottawa, Canada.
# Reference (IEEE):
#  J. Racicot, Enoki. Ottawa, Canada, 2016.
#
# </copyright>
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2016-01-10</date>
# <url>https://github.com/infectedpacket</url>
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
# Imports
#//////////////////////////////////////////////////////////////////////////////
#
import re
import idc
import idaapi
import difflib
import idautils
import logging
#
#//////////////////////////////////////////////////////////////////////////////
# Enoki class
#//////////////////////////////////////////////////////////////////////////////
class Enoki(object):
	"""
		Description: 
			Provides wrapping functions around IDAPython to analyze
		and format structures for unknown/difficult architectures.
		
		Notes:
			Tested on IDA Pro v6.5
			
		Author:
			Jonathan Racicot
			
		Date:
			Created: 2015-10-14
			Updated: 2016-01-10
	"""
	
	#Specifies a 16bit segment
	SEG_16	=	0
	#Specifies a 32bit segment
	SEG_32	=	1
	#Specifies a 64bit segment
	SEG_64	=	2

	#Segment bitness to use when none has been specified.
	DEFAULT_SEGMENT_SIZE = SEG_16
	
	#Specifies a DATA segment
	SEG_DATA = "DATA"
	#Specifies a CODE segment
	SEG_CODE = "CODE"

	SEG_TYPE_CODE = 2
	SEG_TYPE_DATA = 3		
	
	#Used for assessing returns from IDA functions calls.
	FAIL = 0
	SUCCESS = 1

	logger = logging.getLogger(__name__)

	def Enoki(self):
		"""
		Constructor of the Enoki engine. Does nothing.
		"""
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
		backup_file = "{:s}_{:s}.idb".format(input_file, time_string)
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
		r = idc.AddSeg(_startea, _endea, 0, _segsize, 1, 2)
		if (r == Enoki.SUCCESS):
			idc.RenameSeg(_startea, _name) 
			return idc.SetSegmentType(_startea, _type)
		else:
			return Enoki.FAIL
  
	def create_selector(self, _sel, _value):
		return idc.SetSelector(_sel, _value)
  
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
		r = self.create_segment(_startea, _endea, _name, idaapi.SEG_DATA, _segsize)
		if (r == Enoki.SUCCESS):
			return self.set_seg_class_code(_startea)
		return Enoki.FAIL
		
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
		r = self.create_segment(_startea, _endea, _name, idaapi.SEG_CODE, _segsize) 
		if (r == Enoki.SUCCESS):
			return self.set_seg_class_code(_startea)
		return Enoki.FAIL
		
	def set_seg_selector(self, _segea, _sel):
		return self.set_seg_attribute(_segea, SEGATTR_SEL, _sel)
		
	def set_seg_align_para(self, _segea):
		"""
		Sets the alignment of the segment at the given address as 'paragraph', 
		i.e. 16bit.
		
		#param _segea Address within the segment to be modified.
		"""
		return idc.SegAlign(_segea, saRelPara)
		
	def set_seg_class_code(self, _segea):
		"""
		Sets the class of the segment at the given address as containing code. 
		
		#param _segea Address within the segment to be modified.
		"""	
		return self.set_seg_class(_segea, "CODE")
		
	def set_seg_class_data(self, _segea):
		"""
		Sets the class of the segment at the given address as containing data. 
		
		#param _segea Address within the segment to be modified.
		"""		
		return self.set_seg_class(_segea, "DATA")
		
	def set_seg_class(self, _segea, _type):
		"""
		Sets the class of the segment at the given address. 
		
		#param _segea Address within the segment to be modified.
		"""		
		return idc.SegClass(_segea, _type)
		
	def set_seg_attribute(self, _segea, _attr, _value):
		"""
		Sets an attribute to the segment at the given address. The available
		attributes are:
		  SEGATTR_START          starting address
		  SEGATTR_END            ending address
		  SEGATTR_ALIGN          alignment
		  SEGATTR_COMB           combination
		  SEGATTR_PERM           permissions
		  SEGATTR_BITNESS        bitness (0: 16, 1: 32, 2: 64 bit segment)
		  SEGATTR_FLAGS          segment flags
		  SEGATTR_SEL            segment selector
		  SEGATTR_ES             default ES value
		  SEGATTR_CS             default CS value
		  SEGATTR_SS             default SS value
		  SEGATTR_DS             default DS value
		  SEGATTR_FS             default FS value
		  SEGATTR_GS             default GS value
		  SEGATTR_TYPE           segment type
		  SEGATTR_COLOR          segment color
		@param _segea Address within the segment to be modified.
		@param _attr The attribute to change. This is one of the value listed above.
		@param _value The value of the attibute.
		"""
		return idc.SetSegmentAttr(_segea, _attr, _value)
		
	def create_string_at(self, _startea, _unicode=False, _terminator="00"):
		"""
		TODO: Fix unicode strings
		"""
		terminator = "0000"
		strend = self.find_next_byte_string(_startea, terminator)
		if strend != idaapi.BADADDR:
			result = MakeStr(_startea, strend+1)
			if (result == Enoki.FAIL):
				print "[-] Failed to create a string at 0x{:x} to 0x{:x}.".format(_startea, strend+1)
				return Enoki.FAIL
			return Enoki.SUCCESS
		return Enoki.FAIL
		
	def current_file_offset(self):
		"""
		Returns the file offset, i.e. absolute offset from the beginning of the file,
		of the currently selected address.
		@return The absolute offset of the selected address.
		"""
		return idaapi.get_fileregion_offset(ScreenEA())
	
	def min_file_offset(self):
		"""
		Returns the minimum file offset, i.e. absolute offset of the beginning of the file/memory.
		@return The absolute minimum offset of the loaded code.
		"""	
		return idaapi.get_fileregion_offset(MinEA())

	def max_file_offset(self):
		"""
		Returns the maximum file offset, i.e. absolute offset of the end of the file/memory.
		@return The absolute maximum offset of the loaded code.
		"""		
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
		Returns the string, if any, at the specified address.
		@param _ea Address of the string
		@return The string at the specified address.
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
		"""
		Returns the disassembled code at the specified address.
		@param _ea Address of the opcode to disassembled.
		@return String containing the disassembled code.
		"""
		return idc.GetDisasm(_ea)
  
	def get_mnemonic(self, _ea):
		"""
		Returns the instruction at the specified address.
		@param _ea The address from which to retrieve the instruction.
		@return String containing the mnemonic of the instruction.
		"""
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
		"""
		Returns the name of the segment at the specified address.
		@param _ea An address within the segment
		@return String containing the name of the segment.
		"""
		return idc.Segname(_ea)
		
	def get_segment_start(self, _ea):
		"""
		Returns the starting address of the segment located at the specified
		address
		@param _ea An address within the segment
		@return long The starting address of the segment.
		"""
		return idc.SegStart(_ea)
		
	def get_segment_end(self, _ea):
		"""
		Returns the ending address of the segment located at the specified
		address
		@param _ea An address within the segment
		@return long The ending address of the segment.
		"""	
		return idc.SegEnd(_ea)	

	def find_next_byte_string(self, _startea, _bytestr, _fileOffset = False, 
		_bitness=DEFAULT_SEGMENT_SIZE):
		"""
		This function searches for text representing bytes and/or words in the
		machine code of the file from a start address. This function is built on top of the native 
		FindBinary function. The search is conducted starting at the specified address and downward
		for the provided byte string. 
		
		Example:
		e.find_next_byte_string(ScreenEA(), "0000 FFFF ???? 0000")
		
		@param _startea Starting address of the search
		@param _bytestr String to search for
		@param _fileOffset Specifies whether to return found addresses as relative or absolute
				offsets
		@param _bitness Specifies the bitness of the segment.
		@return The offset of the byte string found, or None if there is no search result.
		"""
		offset = None
		ea = _startea;
		if ea == idaapi.BADADDR:
			print ("[-] Failed to retrieve starting address.")
			offset = None
		else:
			block = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, _bytestr, _bitness)
			if (block == idc.BADADDR):
				offset = None
			if _fileOffset:
				offset = idaapi.get_fileregion_offset(block)
			else:
				offset = block
		return offset
		
	def find_byte_string(self, _startea, _endea, _bytestr, 
		_fileOffsets = False, _showmsg = False):
		"""
		This function searches for text representing bytes and/or words in the
		machine code of the file between 2 addresses. This function is built on top of the native 
		FindBinary function. The search is conducted starting at the specified address and downward
		for the provided byte string. 
		
		Example:
		e.find_byte_string(0x4000, 0x8000, "FF FF AA AA FF FF", True)
		
		@param _startea Starting address of the search
		@param _startea Ending address of the search
		@param _bytestr String to search for
		@param _fileOffsets Specifies whether to return found addresses as relative or absolute
				offsets
		@param _showmsg Specifies if the function should print a message with the results
		@return An array of addresses corresponding to the start of the byte string. If none found,
				returns an empty array.
		"""		
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
			return []
			
	def get_code_ranges(self, _startea, _endea, _prolog, _epilog):
		"""
		This function will extract all the machine opcodes located between the
		provided code boundaries in the prescribed range.
		
		Example: TODO
		
		m = e.get_code_ranges(MinEA(), MaxEA(), "4500 4885", "4886 0090")
		print(m)
		[[0x2C00, 0x2C15], [0x2C16, 0x2C38]]
		
		@param _startea The start address of the range to look for code
			segment
		@param _endea The end address of the range to look for code
			segment
		@param _prolog Starting byte string of the code segment to look for.
		@param _epilog Ending byte string of the code segment to look for.
		@return matrix containing the starting and ending addresses of the code
			segment found.
		"""
		segments = []
		if (_startea != BADADDR and _endea != BADADDR):
			prolog_offsets = self.find_byte_string(_startea, _endea, _prolog, False)
			for offset_idx in range(0, len(prolog_offsets)):
				epilog_offset = self.find_next_byte_string(
					prolog_offsets[offset_idx],
					_epilog)
				if epilog_offset != idc.BADADDR:
					segments.append([prolog_offsets[offset_idx], epilog_offset])
		return segments;		
		
	def get_instruction_tokens(self, _ea):
		"""
		Returns the tokens of the disassembled instruction at the specified address.
		
		Example:
		...
		0x2C00:	pop r1	; Pops stack into R1 register
		...
		s = get_instruction_tokens(0x2C00)
		print(s)
		['pop', 'r1', ';', 'Pops', 'stack', 'into', 'R1', 'register']
		
		@param _ea Address of the instruction to disassembled
		@return Array of string containing the tokens of the disassembled instruction.
		"""
		if (_ea != BADADDR):
			return filter(None, GetDisasm(_ea).split(" "))
		
	def get_function_at(self, _ea):
		"""
		Returns the function object at the specified address.
		@param _ea An address within the function
		@return The native IDA function object at the given address.
		"""
		if (_ea != BADADDR):
			return idaapi.get_prev_func(idaapi.get_next_func(_ea).startEA)
		else:
			return None
		
	def get_function_disasm(self, _ea):
		"""
		This function retrieves all of the disassembled and tokenized instructions 
		of the function located at the specified address.
		
		Example:
		...
		0x2C00:	pop r1
		0x2C01: load acc, 0
		0x2C03: jmp 0x2C0A
		...
		s = get_function_disasm(0x2C00)
		print(s)
		[['pop', 'r1'], ['load', 'acc,', '0'], ['jmp', '0x2C0A']]
		
		Note that the tokenization is done using white spaces only, so any commas will remain
		as part of the token.
		
		@param _ea An address within the function.
		@return A matrix of tokenized instructions contained in the function at the specified address.
		
		"""
		matrix_disasm = []
		if (_ea != BADADDR):
			current_func = self.get_function_at(_ea)
			func_start = current_func.startEA
			func_end = current_func.endEA
			for ea in range(func_start, func_end):
				inst_tokens = self.get_instruction_tokens(ea)
				matrix_disasm.append(inst_tokens)
		return matrix_disasm
	
	def compare_code(self, _code1, _code2):
		"""
		The compare_code function provides a similarity ratio between the provided code
		segments. It does so by using the SequenceMatcher from the difflib module, which
		return a value between 0 and 1, 0 indicating 2 completely different segment and 1
		specifying identical code segments.
		
		@param _code1 First code segment to compare
		@param _code2 Seconde code segment to compare
		@return double A value between 0 and 1 indicating the degree of similarity between the
		2 code segments.
		"""
		sm=difflib.SequenceMatcher(None,_code1,_code2,autojunk=False)	
		r = sm.ratio()
		return r
	
	def compare_functions(self, _ea_func1, _ea_func2):
		"""
		Compares the code of 2 functions using the compare_code function. 
		
		@param _ea_func1 Address within the first function to compare
		@param _ea_func2 Address within the second function to compare
		@return double A value between 0 and 1, 0 indicating 2 completely different 
		functions and 1 specifying identical functions.
		"""
		l1 = get_function_instructions(_ea_func1)
		l2 = get_function_instructions(_ea_func2)
		return self.compare_code(l1, l2)
		
	def get_function_instructions(self, _ea):
		"""
		Retrieves the instructions, without operands, of the function located at the
		specified address.
		
		Example:
		...
		0x2C00:	pop r1
		0x2C01: load acc, 0
		0x2C03: jmp 0x2C0A		
		...
		s = e.get_function_instructions(0x2C00)
		print(s)
		['pop', 'load', 'jmp']
				
		@param _ea Address within the function
		@return Array of string representing the instruction of the function.
		"""
		instr = []
		if (_ea != BADADDR):
			instr_matrix = self.get_function_disasm(_ea)
			for line in instr_matrix:
				instr.append(line[0])
		return instr
		
	def get_all_functions_instr(self, _startea, _endea):
		"""
		Extracts the instructions of all functions located between the provided
		start and end addresses. Returns a dictionary in the format 
		<"FunctionName", ['i1', 'i2', ..., 'in']>
		
		@param _startea Starting address
		@param _endea Ending address
		@return A dictionary object. The keys are the name of the functions found
				within the boundaries, while the value is the array of instructions
				for the function.
		"""
		f_instr = {}		
		curEA = _startea
		func = self.get_function_at(_ea)
		
		while (curEA <= _endea):
			name = GetFunctionName(curEA)
			i = self.get_function_instructions(curEA)
			f_instr[name] = i
			func = idaapi.get_next_func(curEA)
			curEA = func.startEA
		return f_instr
		
	def get_all_functions(self, _startea, _endea):
		"""
		Gets all function objects between the provided start and end
		addresses. Returns a dictionary in the format <"FunctionName", FunctionObject>.
		
		@param _startea Starting address
		@param _endea Ending address
		@return A dictionary object. The keys are the name of the functions found
				within the boundaries, while the value is the native Function object
				if IDA.
		"""
		functions = {}
		curEA = _startea
		func = self.get_function_at(_ea)
		while (curEA <= _endea):
			name = GetFunctionName(curEA)
			functions[name] = func
			func = idaapi.get_next_func(curEA)
			curEA = func.startEA
		return functions
		
	def get_all_func_instr_seg(self, _ea=ScreenEA()):
		"""
		Returns all the functions in the segment specified by the provided address. 
		Returns a dictionary in the format <"FunctionName", FunctionObject>.
		
		@param _ea An address within the segment. Default is the segment of the current
				instruction.
		@return A dictionary object. The keys are the name of the functions found
		within the boundaries, while the value is the native Function object
		if IDA.
		"""
		return self.get_all_functions_instr(SegStart(_ea), SegEnd(_ea))
		
	def get_similarity_ratios(self, func1, func2):
		"""
		Calculates the similarity ratios between 2 sets of functions and returns 
		a matrix of the results. The matrix is in the following format:
		
		[
		["f11", "f12", r1]
		["f21", "f22", r2]
		...
		["fn1", "fn2", rn]
		]
		
		Note: this function can take a while to complete and was not design for
		efficiency. O(n^2)
		
		@param func1 First set of function to compare
		@param func2 Second set of function to compare.
		@return Matrix of similarity ratios for each function compared.
		"""
		ratios = []
		for f1, l1 in func1.iteritems():
			for f2, l2 in func2.iteritems():
				r = self.compare_code(l1, l2)
				ratios.append([f1, f2, r])
		return ratios
		
	def get_similarity_func(self, ratios, threshold=1.0):
		"""
		Returns a matrix of similarity vectors with ratios greater or equal
		to the specified threshold.
		
		Example:
		
		ratios = [
		["f11", "f12", 1.0]
		["f21", "f22", 0.64]
		["f31", "f32", 0.85]
		]		
		
		m = e.get_similarity_func(ratios, 0.9)
		print(m)
		[["f11", "f12", 1.0]]	
		
		@param ratios Matrix of ratios as returned by function get_similarity_ratios
		@param threshold Minimum threshold desired. Default value is 1.0
		@return Matrix of similarity ratios with ratio greater or equal to specified threshold.
		"""
		funcs = []
		for r in ratios:
			if (r[2] >= threshold):
				#print("[+] Similarity between '{:s}' and '{:s}': {:f}.".format(r[0], r[1], r[2]))
				funcs.append(r)
		return funcs
		
	def function_is_leaf(self, _funcea):
		"""
		Verifies if the function at the specified address is a leaf function, i.e.
		it does not make any call to other function.
		
		@param _funcea An address within the function
		@return True if the function at the address contains no call instructions.
		"""
		# Retrieves the function at _funcea:
		near_calls = self.get_functions_called_from(_funcea)
		return len(near_calls) == 0
		
	def get_functions_called_by(self, _funcea):
		"""
		Get all functions directly called by the function at the given address. This function
		only extract functions called at the first level, i.e. this function is not recursive.
		Returns a matrix containing the address originating the call, the destination address
		and the name of the function/address called.
		
		Example:
		...
		0x2C00:	pop r1
		0x2C01: load acc, 0
		0x2C03: call 0x2CC0		
		0x2C05: load acc, 27h
		0x2C07: call 0x2D78
		0x2C09: push r1
		0x2C0A: ret
		...
		
		m = e.get_functions_called_by(0x2C00)
		print(m)
		[[0x2C03, 0x2CC0, 'SUB__02CC0'],[0x2C07, 0x2D78, 'SUB__02D78']]
		
		@param _funcea Address within the function
		@return Matrix containing the source, destination and name of the functions called.
		"""
		# Retrieves the function at _funcea:
		func = self.get_function_at(_ea)
		# Boundaries:
		startea = func.startEA
		endea = func.endEA
		# EA index:
		curea = startea
		# Results here:
		near_calls = []
		while (curea < endea):
			for xref in XrefsFrom(curea):
				# Code 17 is the code for 'Code_Near_Jump' type of XREF
				if (xref.type == 17):
					# Add the current address, the address of the call and the 
					# name of the function called.
					call_info = [xref.frm, xref.to, GetFunctionName(xref.to)]
					near_calls.append(call_info)
					print("[*] 0x{:x}: {:s} -> {:s}.".format(
						call_info[0], 
						GetFunctionName(call_info[0]), 
						GetFunctionName(call_info[1])))
			# Next instruction in the function
			curea = NextHead(curea)
		return near_calls
		
	def get_all_sub_functions_called(self, _funcea, _level=0):
		"""
		Get all functions directly and indirectly called by the function at the given address. 
		This function is recursive and will seek all sub function calls as well, therefore this
		function can be time consumming to complete.
		Returns a matrix containing the address originating the call, the destination address
		and the name of the function/address called and the depth of the call from the initial
		function.
		
		Example:
		...
		0x2C00:	pop r1
		0x2C01: load acc, 0
		0x2C03: call 0x2CC0		
		0x2C05: load acc, 27h
		0x2C07: call 0x2D78
		0x2C09: push r1
		0x2C0A: ret
		...
		0x2CC0 SUB__02CC0:
		0x2CC0  pop r1
		0x2CC1  load acc, 00
		0x2CC2  call 0x3DEE
		...
		
		m = e.get_all_sub_functions_called(0x2C00)
		print(m)
		[[0x2C03, 0x2CC0, 'SUB__02CC0', 0],[0x2CC2, 0x3DEE, 'SUB__03DDE', 1],
		 [0x2C07, 0x2D78, 'SUB__02D78', 0]]
		
		@param _funcea Address within the function
		@return Matrix containing the source, destination, name of the functions called and 
		the depth relative to the first function.
		"""	
		# Retrieves the function at _funcea:
		func = idaapi.get_prev_func(idaapi.get_next_func(_funcea).startEA)			
		# Boundaries:
		startea = func.startEA
		endea = func.endEA
		# EA index:
		curea = startea
		# Results here:
		near_calls = []
		while (curea < endea):
			for xref in XrefsFrom(curea):
				# Code 17 is the code for 'Code_Near_Jump' type of XREF
				if (xref.type == 17):
					# Add the current address, the address of the call and the 
					# name of the function called along with the depth.
					call_info = [xref.frm, xref.to, GetFunctionName(xref.to), _level]	
					print("[*]{:s}0x{:x}: {:s} -> {:s}.".format(
						" " * _level,
						call_info[0], 
						GetFunctionName(call_info[0]), 
						GetFunctionName(call_info[1])))				
					sub_calls = self.get_all_sub_functions_called(xref.to, _level+1)
					# Add calls to current ones
					near_calls.append(call_info)
					near_calls.append(sub_calls)
			# Next instruction in the function
			curea = NextHead(curea)
		return near_calls		
			
	def get_functions_leading_to(self, _funcea):
		"""
		This function returns all the functions calling the function at the 
		provided address. This function is not recursive and only returns the
		first depth of function calling. Returns a matrix containing the address 
		originating the call, the destination address and the name of the 
		function/address called.
		
		Example:
		...
		0x2C00: MAIN:
		0x2C00:	pop r1
		0x2C01: load acc, 0
		0x2C03: call 0x2CC0		
		0x2C05: load acc, 27h
		0x2C07: call 0x2D78
		0x2C09: push r1
		0x2C0A: ret
		...
		0x2CC0 SUB__02CC0:
		0x2CC0  pop r1
		0x2CC1  load acc, 00
		0x2CC2  call 0x3DEE
		...
		
		m = e.get_all_sub_functions_called(0x2CC0)
		print(m)
		[[0x2C00, 0x2CC0, 'MAIN']]
		
		@param _funcea Address within the function
		@return Matrix containing the source, destination, name of the functions calling the
		function.
		"""	
		# Retrieves the function at _funcea:
		func = idaapi.get_prev_func(idaapi.get_next_func(_funcea).startEA)	
		# Boundaries:
		startea = func.startEA
		endea = func.endEA
		# EA index:
		curea = startea
		# Results here:
		near_calls = []
		while (curea < endea):
			for xref in XrefsTo(curea):
					# Code 17 is the code for 'Code_Near_Jump' type of XREF
					if (xref.type == 17):
						# Add the current address, the address of the call and the 
						# name of the function called.
						call_info = [xref.frm, xref.to, GetFunctionName(xref.to)]
						near_calls.append(call_info)
						print("[*] 0x{:x}: {:s} -> {:s}.".format(
							call_info[0], 
							GetFunctionName(call_info[0]), 
							GetFunctionName(call_info[1])))
			# Next instruction in the function
			curea = NextHead(curea)
		return near_calls
		

	def save_range_to_file(self, _startea, _endea, _file):
		"""
		Saves the chunk of bytes between the given start and end addresses into
		the given file.
		
		@param _startea The starting address of the chunk
		@param _endea The ending address of the chunk
		@param _file Name of the file to write.
		@return Enoki.SUCCESS if the file was written successfully, Enoki.FAIL
				otherwise.
		"""
		if (_startea != BADADDR and _endea != BADADDR):
			try:
				chunk = bytearray(idc.GetManyBytes(_startea, ((_endea-_startea)+1)*2))
				print("Exporting {:d} bytes chunk 0x{:05x} to 0x{:05x} to {:s}.".format(len(chunk), _startea, _endea, _file))
				with open(_file, "wb") as f:
					f.write(chunk)
			except Exception as e:
				print("[-] Error while writing file: {:s}.".format(e.message))
				return Enoki.FAIL
		return Enoki.SUCCESS