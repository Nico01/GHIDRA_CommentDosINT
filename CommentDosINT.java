import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.Register;

public class CommentDosINT extends GhidraScript {

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(currentProgram.getMemory(), true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Instruction insn = iter.next();
            if (insn.getMnemonicString().contentEquals("INT")
                    && insn.getDefaultOperandRepresentation(0).equals("0x21")) {

                for (var i = insn.getPrevious() ;; i = i.getPrevious()) {
                    if (i == null) {
                        break;
                    }
                    if (i.getMnemonicString().contentEquals("MOV")) {
                        byte int_func = getRegAHContent(i);
                        if (int_func != -1 && int_func < 0x6c) {
                            writeComment(insn, int_func);
                            break;
                        }
                    }
                }
            }
        }
    }

    byte getRegAHContent(Instruction insn) {
        Object[] op0 = insn.getOpObjects(0);
        if (op0.length != 1 || !(op0[0] instanceof Register)) {
            return -1;
        }

        Object[] op1 = insn.getOpObjects(1);
        if (op1.length != 1 || !(op1[0] instanceof Scalar)) {
            return -1;
        }

        Register register = (Register) op0[0];
    
        if (register.getName().contentEquals("AX")) {
            Scalar scalar = (Scalar) op1[0];
            return (byte)(scalar.getValue() >>> 8);
        }

        if (register.getName().contentEquals("AH")) {
            Scalar scalar = (Scalar) op1[0];
            return (byte) scalar.getValue();
        }

        return -1;
    }

    void writeComment(Instruction insn, byte fc) {
        String comment = String.format("DOS Function Codes 0x%02X:\n%s", fc, int21h[fc]);
        insn.setComment(CodeUnit.PLATE_COMMENT, comment);
    }

    private String[] int21h = {
        "Terminate process",                            // 0x00
        "Character input with echo",                    // 0x01
        "Character output",                             // 0x02
        "Auxiliary input",                              // 0x03
        "Auxiliary output",                             // 0x04
        "Printer output",                               // 0x05
        "Direct console i/o",                           // 0x06
        "Unfiltered char i w/o echo",                   // 0x07
        "Character input without echo",                 // 0x08
        "Display string",                               // 0x09
        "Buffered keyboard input",                      // 0x0a
        "Check input status",                           // 0x0b
        "Flush input buffer and then input",            // 0x0c
        "Disk reset",                                   // 0x0d
        "Select disk",                                  // 0x0e
        "Open file",                                    // 0x0f
        "Close file",                                   // 0x10
        "Find first file",                              // 0x11
        "Find next file",                               // 0x12
        "Delete file",                                  // 0x13
        "Sequential read",                              // 0x14
        "Sequential write",                             // 0x15
        "Create file",                                  // 0x16
        "Rename file",                                  // 0x17
        "Reserved",                                     // 0x18
        "Get current disk",                             // 0x19
        "Set DTA address",                              // 0x1a
        "Get default drive data",                       // 0x1b
        "Get drive data",                               // 0x1c
        "Reserved",                                     // 0x1d
        "Reserved",                                     // 0x1e
        "Get disk parameter block for default drive",   // 0x1f
        "Reserved",                                     // 0x20
        "Random read",                                  // 0x21
        "Random write",                                 // 0x22
        "Get file size",                                // 0x23
        "Set relative record number",                   // 0x24
        "Set interrupt vector",                         // 0x25
        "Create new PSP",                               // 0x26
        "Random block read",                            // 0x27
        "Random block write",                           // 0x28
        "Parse filename",                               // 0x29
        "Get date",                                     // 0x2a
        "Set date",                                     // 0x2b
        "Get time",                                     // 0x2c
        "Set time",                                     // 0x2d
        "Set verify flag",                              // 0x2e
        "Get DTA address",                              // 0x2f
        "Get MSDOS version number",                     // 0x30
        "Terminate and stay resident",                  // 0x31
        "Get disk parameter block for specified drive", // 0x32
        "Get or set break flag",                        // 0x33
        "Get InDOS flag pointer",                       // 0x34
        "Get interrupt vector",                         // 0x35
        "Get drive allocation info",                    // 0x36
        "Get or set switch character",                  // 0x37
        "Get or set country info",                      // 0x38
        "Create directory",                             // 0x39
        "Delete directory",                             // 0x3a
        "Set current directory",                        // 0x3b
        "Create file",                                  // 0x3c
        "Open file",                                    // 0x3d
        "Close file",                                   // 0x3e
        "Read file or device",                          // 0x3f
        "Write file or device",                         // 0x40
        "Delete file",                                  // 0x41
        "Set file pointer",                             // 0x42
        "Get or set file attributes",                   // 0x43
        "IOCTL (i/o control)",                          // 0x44
        "Duplicate handle",                             // 0x45
        "Redirect handle",                              // 0x46
        "Get current directory",                        // 0x47
        "Alloate memory block",                         // 0x48
        "Release memory block",                         // 0x49
        "Resize memory block",                          // 0x4a
        "Execute program (exec)",                       // 0x4b
        "Terminate process with return code",           // 0x4c
        "Get return code",                              // 0x4d
        "Find first file",                              // 0x4e
        "Find next file",                               // 0x4f
        "Set current PSP",                              // 0x50
        "Get current PSP",                              // 0x51
        "Get DOS internal pointers (SYSVARS)",          // 0x52
        "Create disk parameter block",                  // 0x53
        "Get verify flag",                              // 0x54
        "Create program PSP",                           // 0x55
        "Rename file",                                  // 0x56
        "Get or set file date & time",                  // 0x57
        "Get or set allocation strategy",               // 0x58
        "Get extended error information",               // 0x59
        "Create temporary file",                        // 0x5a
        "Create new file",                              // 0x5b
        "Lock or unlock file region",                   // 0x5c
        "File sharing functions",                       // 0x5d
        "Get machine name",                             // 0x5e
        "Device redirection",                           // 0x5f
        "Qualify filename",                             // 0x60
        "Reserved",                                     // 0x61
        "Get PSP address",                              // 0x62
        "Get DBCS lead byte table",                     // 0x63
        "Set wait for external event flag",             // 0x64
        "Get extended country information",             // 0x65
        "Get or set code page",                         // 0x66
        "Set handle count",                             // 0x67
        "Commit file",                                  // 0x68
        "Get or set media id",                          // 0x69
        "Commit file",                                  // 0x6a
        "Reserved",                                     // 0x6b
        "Extended open file"                            // 0x6c
    };
}
