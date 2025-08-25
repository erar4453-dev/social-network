import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";

export async function POST(req: Request) {
  const { name, handle, email, password } = await req.json();
  if (!name || !handle || !email || !password || password.length < 6) {
    return NextResponse.json({ error: "Invalid data" }, { status: 400 });
  }
  const exists = await prisma.user.findFirst({ where: { OR: [{ email }, { handle }] } });
  if (exists) return NextResponse.json({ error: "Email или ник уже заняты" }, { status: 409 });

  const hash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { name, handle, email, password: hash }
  });
  return NextResponse.json({ ok: true, user: { id: user.id } });
}
