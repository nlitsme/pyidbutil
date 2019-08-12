#!/usr/bin/perl 

sub filter($)
{
  my $d=$_[0]; $d=~s/[\x00\x0a\x0d\x01-\x1f\x80-\xff]//g;
  return $d;
}

sub sanitize($)
{
  my $d=$_[0];
  $d=~s/&/&amp;/g;
  $d=~s/</&lt;/g;
  $d=~s/\x00//g;
  return $d;
}

my %hexrays=();

if(-f $ARGV[0])
{
  open IN,"python idbtool.py -id0 -v \"$ARGV[0]\" |";
}
elsif(-f "id0safe.txt")
{
  open IN,"<id0safe.txt";
}
else
{
  print STDERR "Usage:\nperl ida2ghidra.pl database.idb >comments.xml\n";
}

while(<IN>)
{
  if(0) # if(m/^\.\s+ff000022 R (\w+) = '([^']+)\x00?'/)
  {
    print "<COMMENT ADDRESS=\"0x$1\" TYPE=\"end-of-line\">$2</COMMENT>\n";
  }

  if(0) #if(m/\s*\d\d:\d\d:\s+(\w+) = (\w+)/)
  {
    my ($a,$b)=($1,$2);
    my $str=pack("H*",substr($b,8)); $str=~s/\x00$//;
    print "$_\n";
    print "$a ".substr($b,0,8)." $str\n\n";
  }
  if(m/2e00(\w+)4100000002 = (\w\w)(\w\w)(\w\w)ff\s/)
  {
    my $dest=sprintf("%06x",unpack("N",pack("H*","00$4$3$2"))-1);
    print STDERR "Mapping function $1 to $dest ($4$3$2)\n";
    $hexrays{$dest}=$1;
  }
  if(m/2eff(\w+)0000000 = (02\w+)/)
  {
    my $function=substr($1,0,6);
    my $realfunc=$hexrays{$function};
    #print "Found Comment\n";
    my $val=pack("H*",$2);
    #print "val: $val\n";
    if(substr($val,-1,1) eq "\x00")
    {
      my $n=unpack("C",substr($val,1,1));
      #print STDERR "Potentially $n comment(s) found: $2\n";
      my $pos=2;
      foreach my $i(1 .. $n)
      {
        my $offset=unpack("C",substr($val,$pos,1));
        #print STDERR "Offset1: $offset\n";
        if($offset>=128) # For those values offset gets 2 bytes
        {
          $offset=(($offset&127)<<8)+unpack("C",substr($val,$pos+1,1));
          $pos++;
        }
        #print STDERR "Offset2: $offset\n";
        $offset--;
        #print STDERR "Offset3: $offset (".sprintf("0x%X",$offset).")\n";
        my $type=unpack("C",substr($val,$pos+1,1));
        my $typetext=($type==0x45)?"end-of-line":($type==0x48)?"pre":($type==0x4A)?"end-of-line":"repeatable";
        my $nextpos=$pos;
        foreach($pos .. length($val)-1)
        {
          last if(substr($val,$_,1) eq "\x00");
          $nextpos++;
        }
        my $addr=sprintf("%x",hex($realfunc)+$offset);
        print STDERR "Comment #$i function:$function -> $realfunc + offset:$offset = $addr ".sprintf("0x%X",$offset)." Type:$typetext : -".filter(substr($val,$pos+2,$nextpos-$pos-1))."-\n";
        print "<COMMENT ADDRESS=\"0x$addr\" TYPE=\"$typetext\">".sanitize(substr($val,$pos+2,$nextpos-$pos-1))."</COMMENT>\n";
        $pos=$nextpos+1;
      } 
    }
  }

  if(m/ = (\w+)/)
  {
  #  my $val=pack("H*",$1);
  #  print "Text ".filter($_)." text:".filter($val)."\n";
  }

}


