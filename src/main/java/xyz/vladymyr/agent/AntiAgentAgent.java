package xyz.vladymyr.agent;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import xyz.vladymyr.agent.transformer.FilteredTransformer;
import xyz.vladymyr.agent.transformer.Transformer;

import java.io.IOException;
import java.lang.instrument.*;
import java.lang.invoke.MethodType;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <h2>Anti-Agent Agent</h2>
 * The main purpose of this agent is to disable other agents from interacting with loading classes, this is accomplished
 * by cleaning their transform method. I included a few other transformers as an extra for security purposes.
 * You always can make your own {@link Transformer} built using Builder.
 * <p>
 * There is already an easy way using <code>-XX:+DisableAttachMechanism</code> in the JVM arguments.
 * The problem with that solutions is that it can easily be bypassed modifying the program's bytecode to make it not relaunch itself like that
 * or by directly removing the check from OpenJDK's source.
 * <p>
 * Remember that went launching your program -javaagent argument must be before -jar
 *
 * @author Vladymyr
 * @version 01/10/2019
 * @see java.lang.instrument.ClassFileTransformer
 * @since 1.0
 */
public enum AntiAgentAgent implements ClassFileTransformer {
	INSTANCE;

	/**
	 * @see ClassFileTransformer#transform
	 */
	private final static String CLASS_TRANSFORMER_METHOD_NAME = "transform";

	/**
	 * Bytecode descriptor representation of {@link ClassFileTransformer#transform(ClassLoader, String, Class, ProtectionDomain, byte[])}
	 */
	private final static String CLASS_TRANSFORMER_METHOD_DESC = MethodType
			.methodType(byte[].class, ClassLoader.class, String.class, Class.class, ProtectionDomain.class, byte[].class)
			.toMethodDescriptorString();

	/**
	 * Transformer in charge of emptying {@link ClassFileTransformer#transform(ClassLoader, String, Class, ProtectionDomain, byte[])}
	 * method due us wanting to prevent other agents. Works with lambda expressions too.
	 */
	private final static Transformer CLASS_TRANSFORMER_CLEANER = Transformer.builder()
			.withClassFilter((Class<?> cls, ClassNode classNode) -> {
				boolean notNull = classNode != null;
				boolean needsUpdate = false;

				if (notNull) {
					// Micro-optimizations
					String classTransformerDesc = CLASS_TRANSFORMER_METHOD_DESC;
					String classTransformerName = CLASS_TRANSFORMER_METHOD_NAME;

					Map<String, String> invokeDynamicMethods = new HashMap<>();
					for (MethodNode methodNode : classNode.methods) {
						InsnList methodInstructions = methodNode.instructions;
						AbstractInsnNode[] array = methodInstructions.toArray();
						for (AbstractInsnNode insn : array) {
							if (insn instanceof InvokeDynamicInsnNode) {
								InvokeDynamicInsnNode methodInsn = (InvokeDynamicInsnNode) insn;
								if (methodInsn.desc.equals("()Ljava/lang/instrument/ClassFileTransformer;")
										&& methodInsn.name.equals(classTransformerName)) {
									Object[] bsmArgs = methodInsn.bsmArgs;
									if (bsmArgs == null && bsmArgs.length < 2) {
										continue;
									}

									Type type = bsmArgs[0] instanceof Type ? (Type) bsmArgs[0] : null;
									Handle handle = bsmArgs[1] instanceof Handle ? (Handle) bsmArgs[1] : null;

									if (type == null || handle == null) {
										continue;
									}

									if (handle.getTag() == Opcodes.H_INVOKESTATIC
											&& type.getDescriptor().equals(classTransformerDesc)
											&& handle.getDesc().equals(classTransformerDesc)) {
										// We assume the method is inside the same class
										invokeDynamicMethods.put(handle.getName(), classTransformerDesc);
									}
								}
							}
						}
					}

					if (!invokeDynamicMethods.isEmpty()) {
						for (MethodNode methodNode : classNode.methods) {
							if (invokeDynamicMethods.containsKey(methodNode.name) && invokeDynamicMethods.containsValue(methodNode.desc)) {
								Transformer.CLEANER.emptyMethod(methodNode);

								// Maybe the other criteria are invalid but we still need to update the class
								// in order to clean the transformer method
								needsUpdate = true;
							}
						}
					}
				}

				return needsUpdate
						// I though of checking the sub-class interface's too but I realized they will be
						// loaded and processed too, so just by doing this should be enough
						|| notNull && classNode.interfaces.contains("java/lang/instrument/ClassFileTransformer")
						// It only allows this class file transformer, add more if you want allow other
						|| ClassFileTransformer.class.isAssignableFrom(cls) && !cls.equals(AntiAgentAgent.class) && cls != ClassFileTransformer.class;
			})
			.withMethodFilter(methodNode -> methodNode.name.equals(CLASS_TRANSFORMER_METHOD_NAME)
					&& methodNode.desc.equals(CLASS_TRANSFORMER_METHOD_DESC))
			.transformer(Transformer.CLEANER)
			.build();

	/**
	 * @see Thread#dumpStack()
	 */
	private final static String THREAD_DUMP_STACK_METHOD_NAME = "dumpStack";

	/**
	 * Bytecode descriptor representation of {@link Thread#dumpStack()}
	 */
	private final static String THREAD_DUMP_STACK_METHOD_DESC = MethodType.methodType(void.class)
			.toMethodDescriptorString();

	/**
	 * Transformer in charge of emptying {@link Thread#dumpStack()} method due it's possible
	 * use for reverse engineering.
	 */
	private final static Transformer THREAD_DUMP_STACK_CLEANER = Transformer
			.builder()
			.withClassFilter((Class<?> cls, ClassNode classNode) -> cls == Thread.class)
			.withMethodFilter(methodNode -> methodNode.name.equals(THREAD_DUMP_STACK_METHOD_NAME)
					&& methodNode.desc.equals(THREAD_DUMP_STACK_METHOD_DESC))
			.transformer(Transformer.CLEANER)
			.build();

	/**
	 * Transform wanted classes before they get defined by the JVM
	 */
	public final static List<Transformer> TRANSFORMERS = new ArrayList<>();

	/**
	 * Transformers to redefine already loaded classes
	 */
	public final static List<Transformer> REDEFINERS = new ArrayList<>();

	/**
	 * I don't use this for anything, but maybe you will. The idea was to avoid transforming classes that were
	 * re-defined but dynamically loaded classes can have the same name so it would be a way to bypass the agent.
	 */
	public final static List<String> LOADED_TRANSFORMED_CLASSES = new ArrayList<>();


	/**
	 * Adds the required transformers, redefiners and runs starts the agent
	 *
	 * @param args given arguments (ignored)
	 * @param inst given instrumentation
	 * @throws ClassNotFoundException     should never be thrown (present for compatibility reasons only in {@link Instrumentation#redefineClasses})
	 * @throws UnmodifiableClassException should never be thrown since we already already check if the class is modifiable using {@link Instrumentation#isModifiableClass(Class)}
	 * @throws IOException                thrown by {@link ClassReader} if there was an error during the parsing process
	 */
	public static void premain(String args, Instrumentation inst) throws ClassNotFoundException, UnmodifiableClassException, IOException {
		TRANSFORMERS.add(CLASS_TRANSFORMER_CLEANER);

		REDEFINERS.add(CLASS_TRANSFORMER_CLEANER);
		REDEFINERS.add(THREAD_DUMP_STACK_CLEANER);

		INSTANCE.start(inst);
	}

	/**
	 * Registers itself as a {@link ClassFileTransformer} and tries to redefine already loaded class if possible and necessary.
	 *
	 * @param inst given instrumentation
	 * @throws ClassNotFoundException     should never be thrown (present for compatibility reasons only in {@link Instrumentation#redefineClasses})
	 * @throws UnmodifiableClassException should never be thrown since we already already check if the class is modifiable using {@link Instrumentation#isModifiableClass(Class)}
	 * @throws IOException                thrown by {@link ClassReader} if there was an error during the parsing process
	 */
	public void start(Instrumentation inst) throws IOException, UnmodifiableClassException, ClassNotFoundException {
		inst.addTransformer(INSTANCE);

		// We must have the attribute 'Can-Redefine-Classes'set to true in MANIFEST.MF file
		if (inst.isRedefineClassesSupported()) {
			List<ClassDefinition> classDefinitions = new ArrayList<>();
			for (Class<?> cls : inst.getAllLoadedClasses()) {
				if (inst.isModifiableClass(cls)) {
					ClassNode node = null;
					List<Transformer> transformers = new ArrayList<>();
					for (int i = 0, redefinersSize = REDEFINERS.size(); i < redefinersSize; i++) {
						Transformer transformer = REDEFINERS.get(i);
						if (transformer instanceof FilteredTransformer) {
							// I don't like this but it's the only way to avoid an exception thrown by the class reader when it will try
							// to read an anonymous class. Those type are transient to any classloader, it won't be able to find it.
							// I don't do this on the normal transforming method because in that case they weren't
							// created yet, allowing me to disable them. This is the only issue I don't know how to fix.
							// If we wanna stay positive, at least I don't try to read classes that can't pass the normal class validation.
							if (!((FilteredTransformer) transformer).validateClass(cls, null)) {
								continue;
							}

							if (node == null) {
								node = readClass(cls.getName());
							}

							if (!((FilteredTransformer) transformer).validateClass(cls, node)) {
								continue;
							}

						}

						if (node == null) {
							node = readClass(cls.getName());
						}

						transformers.add(transformer);
					}

					if (!transformers.isEmpty()) {
						classDefinitions.add(new ClassDefinition(cls, transform(node, transformers.toArray(new Transformer[transformers.size()]))));
					}
				}
			}

			inst.redefineClasses(classDefinitions.toArray(new ClassDefinition[classDefinitions.size()]));
		}
	}

	/**
	 * @param name the fully qualified name of the class to be read. It doesn't matter if it uses `.` or `/`, the {@link ClassReader}
	 *             will take care of replacing that before calling {@link ClassLoader#getSystemResourceAsStream}.
	 * @return node containing all classes's cata
	 * @throws IOException thrown by {@link ClassReader} if there was an error during the parsing
	 *                     process, such as trying to read an anonymous class
	 */
	private ClassNode readClass(String name) throws IOException {
		ClassReader reader = new ClassReader(name);
		ClassNode node = new ClassNode();
		reader.accept(node, ClassReader.SKIP_FRAMES);
		return node;
	}

	/**
	 * Applies given transformers to the class node
	 *
	 * @param node         class node to process
	 * @param transformers transformers to apply to node's methods
	 * @return transformed class
	 */
	private byte[] transform(ClassNode node, Transformer... transformers) {
		for (MethodNode method : node.methods) {
			for (Transformer transformer : transformers) {
				if (transformer instanceof FilteredTransformer
						&& !((FilteredTransformer) transformer).validateMethod(method)) {
					continue;
				}

				transformer.process(method);
			}
		}

		ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
		node.accept(writer);

		LOADED_TRANSFORMED_CLASSES.add(node.name);
		return writer.toByteArray();
	}

	/**
	 * Implementation of {@link ClassFileTransformer#transform(ClassLoader, String, Class, ProtectionDomain, byte[])} with the objective of
	 * transforming the supplied class file with the provided transformers and return replacement.
	 *
	 * @param loader              current class loader
	 * @param className           loading class name, can be null
	 * @param classBeingRedefined pretty self-explanatory
	 * @param protectionDomain    domain of the class being defined
	 * @param classfileBuffer     byte buffer (ignore, must not be modified)
	 * @return Either null meaning no modifications or the bytes of a transformed version of the supplied class
	 * @throws IllegalClassFormatException
	 */
	@Override
	public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
		if (className != null /* && !LOADED_TRANSFORMED_CLASSES.contains(className) */) {
			try {
				ClassNode node = readClass(className);
				List<Transformer> transformers = new ArrayList<>();
				for (int i = 0, transformersSize = TRANSFORMERS.size(); i < transformersSize; i++) {
					Transformer transformer = TRANSFORMERS.get(i);
					if (transformer instanceof FilteredTransformer
							&& !((FilteredTransformer) transformer).validateClass(classBeingRedefined, node)) {
						continue;
					}

					transformers.add(transformer);
				}

				if (!transformers.isEmpty()) {
					return transform(node, transformers.toArray(new Transformer[transformers.size()]));
				}
			} catch (IOException e) {
				// Print stack trace
				e.printStackTrace();
			}
		}

		// No changes
		return null;
	}
}
